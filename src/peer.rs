pub mod extensions;
mod messages;
use self::extensions::*;
use self::messages::*;
use crate::consts::{
    CLIENT, MAX_PEER_MSG_LEN, PEER_CONNECT_TIMEOUT, SUPPORTED_EXTENSIONS, UT_METADATA,
};
use crate::torrent::*;
use crate::types::{InfoHash, LocalPeer, PeerId};
use bendy::decoding::{Error as BendyError, FromBencode, Object, ResultExt};
use bytes::{Bytes, BytesMut};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use std::fmt;
use std::net::{AddrParseError, IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::codec::{
    length_delimited::{Builder, LengthDelimitedCodec},
    Framed,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Peer {
    address: SocketAddr,
    id: Option<PeerId>,
}

impl Peer {
    pub(crate) async fn get_metadata_info(
        &self,
        info_hash: &InfoHash,
        local: &LocalPeer,
    ) -> Result<TorrentInfo, PeerError> {
        log::info!("Requesting info for {info_hash} from {self}");
        self.connect(info_hash, local)
            .await?
            .get_metadata_info()
            .await
    }

    async fn connect<'a>(
        &'a self,
        info_hash: &'a InfoHash,
        local: &LocalPeer,
    ) -> Result<PeerConnection<'a>, PeerError> {
        log::debug!("Connecting to {self}");
        let mut s = match timeout(PEER_CONNECT_TIMEOUT, TcpStream::connect(&self.address)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(PeerError::Connect(e)),
            Err(_) => return Err(PeerError::ConnectTimeout),
        };
        log::trace!("Connected to {self}");
        log::trace!("Sending handshake to {self}");
        let msg = Handshake::new(SUPPORTED_EXTENSIONS, info_hash, &local.id);
        s.write_all_buf(&mut Bytes::from(msg))
            .await
            .map_err(PeerError::Send)?;
        s.flush().await.map_err(PeerError::Send)?;
        let mut buf = BytesMut::zeroed(Handshake::LENGTH);
        let _ = s.read_exact(&mut buf).await.map_err(PeerError::Recv)?;
        let msg = Handshake::try_from(buf.freeze())?;
        log::trace!("{self} sent {msg}");
        if &msg.info_hash != info_hash {
            return Err(PeerError::InfoHashMismatch {
                expected: info_hash.clone(),
                got: msg.info_hash,
            });
        }
        let extensions = ExtensionSet::from_iter(SUPPORTED_EXTENSIONS) & msg.extensions;
        if !extensions.has(Extension::Bep10) {
            return Err(PeerError::NoBep10);
        }
        let local_registry = {
            let mut registry = Bep10Registry::new();
            registry
                .register(Bep10Extension::Metadata, UT_METADATA)
                .unwrap();
            registry
        };
        let msg = Message::from(ExtendedHandshake {
            m: Some(local_registry.to_m()),
            v: Some(CLIENT.into()),
            metadata_size: None,
        });
        let mut channel = MessageChannel::new(self, s, local_registry);
        channel.send(msg).await?;
        let msg = channel.recv().await?;
        // TODO: Look into how acceptable/widespread it is for the extended
        // handshake to not be the packet immediately after the protocol
        // handshake
        let Message::Extended(ExtendedMessage::Handshake(shake)) = msg else {
            return Err(PeerError::NoExtendedHandshake);
        };
        let metadata_size = shake.metadata_size;
        let remote_registry = shake.into_bep10_registry()?;
        if !remote_registry.contains(Bep10Extension::Metadata) {
            return Err(PeerError::NoMetadataExt);
        }
        channel.set_remote_registry(remote_registry);
        if extensions.has(Extension::Fast) {
            channel.send(Message::Core(CoreMessage::HaveNone)).await?;
        }
        Ok(PeerConnection {
            channel,
            extensions,
            info_hash,
            metadata_size,
        })
    }
}

impl FromStr for Peer {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Peer, AddrParseError> {
        let address = s.parse::<SocketAddr>()?;
        Ok(Peer { address, id: None })
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Peer {}>", self.address)
    }
}

impl From<SocketAddrV4> for Peer {
    fn from(addr: SocketAddrV4) -> Peer {
        Peer {
            address: addr.into(),
            id: None,
        }
    }
}

impl From<SocketAddrV6> for Peer {
    fn from(addr: SocketAddrV6) -> Peer {
        Peer {
            address: addr.into(),
            id: None,
        }
    }
}

impl FromBencode for Peer {
    fn decode_bencode_object(object: Object) -> Result<Peer, BendyError> {
        let mut peer_id = None;
        let mut ip = None;
        let mut port = None;
        let mut dd = object.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            match kv {
                (b"peer id", v) => {
                    let buf = v.try_into_bytes().context("peer id")?.to_vec();
                    match PeerId::try_from(Bytes::from(buf)) {
                        Ok(id) => {
                            peer_id = Some(id);
                        }
                        Err(e) => {
                            return Err(
                                BendyError::malformed_content(Box::new(e)).context("peer id")
                            )
                        }
                    }
                }
                (b"ip", v) => {
                    let s = match std::str::from_utf8(v.try_into_bytes().context("peer id")?) {
                        Ok(s) => s,
                        Err(e) => {
                            return Err(BendyError::malformed_content(Box::new(e)).context("ip"))
                        }
                    };
                    // Note that BEP 3 technically allows non-compact `ip`
                    // values to be domain names as well, but we're not
                    // supporting that.
                    match s.parse::<IpAddr>() {
                        Ok(ipaddr) => {
                            ip = Some(ipaddr);
                        }
                        Err(e) => {
                            return Err(BendyError::malformed_content(Box::new(e)).context("ip"))
                        }
                    }
                }
                (b"port", v) => {
                    port = Some(u16::decode_bencode_object(v).context("port")?);
                }
                _ => (),
            }
        }
        let ip = ip.ok_or_else(|| BendyError::missing_field("ip"))?;
        let port = port.ok_or_else(|| BendyError::missing_field("port"))?;
        Ok(Peer {
            address: SocketAddr::new(ip, port),
            id: peer_id,
        })
    }
}

#[derive(Debug)]
struct MessageChannel<'a> {
    peer: &'a Peer,
    inner: Framed<TcpStream, LengthDelimitedCodec>,
    local_registry: Bep10Registry,
    remote_registry: Bep10Registry,
}

impl<'a> MessageChannel<'a> {
    fn new(peer: &'a Peer, s: TcpStream, local_registry: Bep10Registry) -> Self {
        let inner = Builder::new()
            .big_endian()
            .max_frame_length(MAX_PEER_MSG_LEN)
            .length_field_type::<u32>()
            .new_framed(s);
        MessageChannel {
            peer,
            inner,
            local_registry,
            remote_registry: Bep10Registry::new(),
        }
    }

    fn set_remote_registry(&mut self, registry: Bep10Registry) {
        self.remote_registry = registry;
    }

    async fn send(&mut self, msg: Message) -> Result<(), PeerError> {
        log::trace!("Sending to {}: {}", self.peer, msg);
        let buf = msg
            .encode(&self.remote_registry)
            .expect("We should not send any extended messages the other side can't handle");
        self.inner.send(buf).await.map_err(PeerError::Send)
    }

    async fn recv(&mut self) -> Result<Message, PeerError> {
        let msg = match self.inner.next().await {
            Some(Ok(buf)) => Message::decode(buf.freeze(), &self.local_registry)?,
            Some(Err(e)) => return Err(PeerError::Recv(e)),
            None => return Err(PeerError::Disconnect),
        };
        log::trace!("{} sent message: {}", self.peer, msg);
        Ok(msg)
    }
}

#[derive(Debug)]
struct PeerConnection<'a> {
    channel: MessageChannel<'a>,
    extensions: ExtensionSet,
    info_hash: &'a InfoHash,
    metadata_size: Option<u32>,
}

impl<'a> PeerConnection<'a> {
    async fn get_metadata_info(&mut self) -> Result<TorrentInfo, PeerError> {
        // Unlike a normal torrent, we expect to get the entire info from a
        // single peer and error if it can't give it to us (because peers
        // should only be sending any info if they've checked the whole thing,
        // and if they can't send it all, why should we trust them?)
        let Some(metadata_size) = self.metadata_size else {
            return Err(PeerError::NoMetadataSize);
        };
        let mut piecer = TorrentInfoBuilder::new(self.info_hash.clone(), metadata_size)?;
        while let Some(i) = piecer.next_piece() {
            let msg = Message::from(MetadataMessage::Request { piece: i });
            self.channel.send(msg).await?;
            loop {
                let msg = self.channel.recv().await?;
                match msg {
                    Message::Extended(ExtendedMessage::Metadata(msg)) => match msg {
                        MetadataMessage::Data {
                            piece,
                            total_size,
                            payload,
                        } => {
                            if total_size != metadata_size {
                                return Err(PeerError::SizeMismatch {
                                    handshake: metadata_size,
                                    data: total_size,
                                });
                            }
                            if piece != i {
                                return Err(PeerError::WrongPiece {
                                    expected: i,
                                    got: piece,
                                });
                            }
                            piecer.push(payload)?;
                            break;
                        }
                        MetadataMessage::Reject { piece } => {
                            if piece != i {
                                return Err(PeerError::WrongPiece {
                                    expected: i,
                                    got: piece,
                                });
                            }
                            return Err(PeerError::InfoRequestRejected { piece });
                        }
                        MetadataMessage::Request { piece } => {
                            log::trace!(
                                "Rejecting request for metadata info piece {piece} from {}",
                                self.channel.peer
                            );
                            let msg = Message::from(MetadataMessage::Reject { piece });
                            self.channel.send(msg).await?;
                        }
                        MetadataMessage::Unknown { .. } => (),
                    },
                    msg if msg.can_be_ignored() => (),
                    msg => return Err(PeerError::Unexpected(msg.to_string())),
                }
            }
        }
        let info = piecer.build()?;
        log::info!(
            "Metadata for {} received from {}",
            self.info_hash,
            self.channel.peer
        );
        Ok(info)
    }
}

#[derive(Debug, Error)]
pub(crate) enum PeerError {
    #[error("could not connect to peer")]
    Connect(std::io::Error),
    #[error("timed out trying to connect to peer")]
    ConnectTimeout,
    #[error("error sending message to peer")]
    Send(std::io::Error),
    #[error("error receiving message from peer")]
    Recv(std::io::Error),
    #[error("peer sent wrong info hash in handshake; expected {expected}, got {got}")]
    InfoHashMismatch { expected: InfoHash, got: InfoHash },
    #[error("peer does not support BEP 10 extensions")]
    NoBep10,
    #[error("peer did not send extended handshake")]
    NoExtendedHandshake,
    #[error("peer does not support sending metadata")]
    NoMetadataExt,
    #[error("peer suddenly disconnected")]
    Disconnect,
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    #[error("peer sent invalid message")]
    Message(#[from] MessageError),
    #[error("peer sent extended handshake with inconsistent \"m\" dict")]
    Registry(#[from] Bep10RegistryError),
    #[error("peer did not report info size in extended handshake")]
    NoMetadataSize,
    #[error(transparent)]
    InfoConstruct(#[from] ConstructError),
    #[error(transparent)]
    InfoPush(#[from] PushError),
    #[error("peer sent invalid torrent metadata")]
    InfoBuild(#[from] BuildError),
    #[error("peer declared total metadata size as {handshake} in extended handshake but as {data} in metadata data message")]
    SizeMismatch { handshake: u32, data: u32 },
    #[error("request for metadata piece {expected} was replied to with message for piece {got}")]
    WrongPiece { expected: u32, got: u32 },
    #[error("request for metadata piece {piece} was rejected")]
    InfoRequestRejected { piece: u32 },
    #[error("peer sent unexpected message: {0}")]
    Unexpected(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{decode_bencode, UnbencodeError};

    #[test]
    fn test_unbencode_peer() {
        let peer = decode_bencode::<Peer>(
            b"d2:ip9:127.0.0.17:peer id20:-PRE-123-abcdefghijk4:porti8080ee",
        )
        .unwrap();
        assert_eq!(
            peer.address,
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            peer.id,
            Some(PeerId::try_from(Bytes::from(b"-PRE-123-abcdefghijk".as_slice())).unwrap())
        );
    }

    #[test]
    fn test_unbencode_peer_no_peer_id() {
        let peer = decode_bencode::<Peer>(b"d2:ip9:127.0.0.14:porti8080ee").unwrap();
        assert_eq!(
            peer.address,
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(peer.id, None);
    }

    #[test]
    fn test_unbencode_peer_extra_field() {
        let peer = decode_bencode::<Peer>(
            b"d2:ip9:127.0.0.17:peer id20:-PRE-123-abcdefghijk4:porti8080e5:speedi65535ee",
        )
        .unwrap();
        assert_eq!(
            peer.address,
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            peer.id,
            Some(PeerId::try_from(Bytes::from(b"-PRE-123-abcdefghijk".as_slice())).unwrap())
        );
    }

    #[test]
    fn test_unbencode_peer_empty() {
        assert!(matches!(
            decode_bencode::<Peer>(b""),
            Err(UnbencodeError::NoData)
        ));
    }

    #[test]
    fn test_unbencode_peer_trailing_bencode() {
        let r = decode_bencode::<Peer>(
            b"d2:ip9:127.0.0.17:peer id20:-PRE-123-abcdefghijk4:porti8080ee2:hi",
        );
        assert!(matches!(r, Err(UnbencodeError::TrailingData)));
    }

    #[test]
    fn test_unbencode_peer_trailing_garbage() {
        let r = decode_bencode::<Peer>(
            b"d2:ip9:127.0.0.17:peer id20:-PRE-123-abcdefghijk4:porti8080eeqqq",
        );
        assert!(matches!(r, Err(UnbencodeError::TrailingData)));
    }
}
