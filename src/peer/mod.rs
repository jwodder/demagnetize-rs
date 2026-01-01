pub(crate) mod extensions;
mod messages;
pub(crate) mod msepe;
use self::extensions::*;
use self::messages::*;
use crate::app::App;
use crate::consts::{CLIENT, MAX_PEER_MSG_LEN, SUPPORTED_EXTENSIONS, UT_METADATA};
use crate::torrent::*;
use crate::types::{InfoHash, InfoHashProvider, PeerId};
use crate::util::ErrorChain;
use bendy::decoding::{Error as BendyError, FromBencode, Object, ResultExt};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use rand::{SeedableRng, rngs::StdRng};
use std::fmt::{self, Write};
use std::net::{AddrParseError, IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::{
    codec::{
        Framed,
        length_delimited::{Builder, LengthDelimitedCodec},
    },
    either::Either,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CryptoMode {
    Encrypt,
    Prefer,
    Plain,
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub(crate) struct Peer {
    pub(crate) address: SocketAddr,
    pub(crate) id: Option<PeerId>,
    pub(crate) requires_crypto: bool,
}

impl Peer {
    pub(crate) fn display_json(&self) -> DisplayJson<'_> {
        DisplayJson(self)
    }

    pub(crate) fn info_getter<H: InfoHashProvider>(
        &self,
        info_hash: H,
        app: Arc<App>,
    ) -> InfoGetter<'_, H> {
        InfoGetter {
            peer: self,
            info_hash,
            app,
            crypto_mode: None,
        }
    }
}

impl FromStr for Peer {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Peer, AddrParseError> {
        let address = s.parse::<SocketAddr>()?;
        Ok(Peer {
            address,
            id: None,
            requires_crypto: false,
        })
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<Peer {}>", self.address)
    }
}

impl From<SocketAddr> for Peer {
    fn from(address: SocketAddr) -> Peer {
        Peer {
            address,
            id: None,
            requires_crypto: false,
        }
    }
}

impl From<SocketAddrV4> for Peer {
    fn from(addr: SocketAddrV4) -> Peer {
        Peer {
            address: addr.into(),
            id: None,
            requires_crypto: false,
        }
    }
}

impl From<SocketAddrV6> for Peer {
    fn from(addr: SocketAddrV6) -> Peer {
        Peer {
            address: addr.into(),
            id: None,
            requires_crypto: false,
        }
    }
}

impl FromBencode for Peer {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<Peer, BendyError> {
        let mut peer_id = None;
        let mut ip = None;
        let mut port = None;
        let mut dd = object.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            match kv {
                (b"peer id", v) => {
                    let buf = v.try_into_bytes().context("peer id")?;
                    match PeerId::try_from(buf) {
                        Ok(id) => {
                            peer_id = Some(id);
                        }
                        Err(e) => return Err(BendyError::malformed_content(e).context("peer id")),
                    }
                }
                (b"ip", v) => {
                    let s = match std::str::from_utf8(v.try_into_bytes().context("peer id")?) {
                        Ok(s) => s,
                        Err(e) => return Err(BendyError::malformed_content(e).context("ip")),
                    };
                    // Note that BEP 3 technically allows non-compact `ip`
                    // values to be domain names as well, but we're not
                    // supporting that.
                    match s.parse::<IpAddr>() {
                        Ok(ipaddr) => {
                            ip = Some(ipaddr);
                        }
                        Err(e) => return Err(BendyError::malformed_content(e).context("ip")),
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
            requires_crypto: false,
        })
    }
}

#[derive(Debug)]
pub(crate) struct InfoGetter<'a, H> {
    peer: &'a Peer,
    info_hash: H,
    app: Arc<App>,
    crypto_mode: Option<CryptoMode>,
}

impl<'a, H: InfoHashProvider> InfoGetter<'a, H> {
    pub(crate) fn crypto_mode(mut self, mode: Option<CryptoMode>) -> Self {
        self.crypto_mode = mode;
        self
    }

    fn get_crypto_mode(&self) -> Result<CryptoMode, PeerError> {
        if let Some(cs) = self.crypto_mode {
            match (cs, self.peer.requires_crypto) {
                (CryptoMode::Prefer, true) => Ok(CryptoMode::Encrypt),
                (CryptoMode::Plain, true) => Err(PeerError::CantRequireCrypto),
                (cs, _) => Ok(cs),
            }
        } else {
            self.app
                .get_crypto_mode(self.peer.requires_crypto)
                .ok_or(PeerError::CantRequireCrypto)
        }
    }

    pub(crate) async fn run(self) -> Result<TorrentInfo<H>, PeerError> {
        log::info!("Requesting info for {} from {}", self.info_hash, self.peer);
        let handshake_timeout = self.app.cfg.peers.handshake_timeout;
        let r = match self.get_crypto_mode()? {
            CryptoMode::Encrypt => timeout(handshake_timeout, self.connect(true)).await,
            CryptoMode::Prefer => match timeout(handshake_timeout, self.connect(true)).await {
                Ok(Err(e @ PeerError::CryptoHandshake(_))) => {
                    log::warn!(
                        "Encryption handshake with {} failed: {}; will try unencrypted connection",
                        self.peer,
                        ErrorChain(e)
                    );
                    timeout(handshake_timeout, self.connect(false)).await
                }
                r => r,
            },
            CryptoMode::Plain => timeout(handshake_timeout, self.connect(false)).await,
        };
        match r {
            Ok(Ok(mut conn)) => conn.get_metadata_info().await,
            Ok(Err(e)) => Err(e),
            Err(_) => Err(PeerError::ConnectTimeout),
        }
    }

    async fn connect(&self, encrypt: bool) -> Result<PeerConnection<'a, H>, PeerError> {
        log::debug!("Connecting to {}", self.peer);
        let s = TcpStream::connect(&self.peer.address)
            .await
            .map_err(PeerError::Connect)?;
        log::trace!("Connected to {}", self.peer);
        let mut s = if encrypt {
            log::debug!("Encrypting connection to {} ...", self.peer);
            Either::Right(
                msepe::EncryptedStream::handshake(
                    s,
                    msepe::HandshakeBuilder::new(
                        *self.peer,
                        self.info_hash.get_info_hash(),
                        StdRng::from_os_rng(),
                    )
                    .dh_exchange_timeout(self.app.cfg.peers.dh_exchange_timeout),
                )
                .await?,
            )
        } else {
            Either::Left(s)
        };
        log::trace!("Sending handshake to {}", self.peer);
        let msg = Handshake::new(
            SUPPORTED_EXTENSIONS,
            self.info_hash.get_info_hash(),
            self.app.local.id,
        );
        s.write_all_buf(&mut Bytes::from(msg))
            .await
            .map_err(PeerError::Send)?;
        s.flush().await.map_err(PeerError::Send)?;
        let mut buf = BytesMut::zeroed(Handshake::LENGTH);
        let _ = s.read_exact(&mut buf).await.map_err(PeerError::Recv)?;
        let msg = Handshake::try_from(buf.freeze())?;
        log::trace!("{} sent {msg}", self.peer);
        if msg.info_hash != self.info_hash.get_info_hash() {
            return Err(PeerError::InfoHashMismatch {
                expected: self.info_hash.get_info_hash(),
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
                .expect("registering a non-zero code in a new registry should not fail");
            registry
        };
        let msg = Message::from(ExtendedHandshake {
            e: None,
            m: Some(local_registry.to_m()),
            v: Some(CLIENT.into()),
            metadata_size: None,
            yourip: Some(self.peer.address.ip()),
        });
        let mut channel = MessageChannel::new(self.peer, s, local_registry);
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
            info_hash: self.info_hash.clone(),
            metadata_size,
        })
    }
}

struct MessageChannel<'a> {
    peer: &'a Peer,
    inner: Framed<Either<TcpStream, msepe::EncryptedStream>, LengthDelimitedCodec>,
    local_registry: Bep10Registry,
    remote_registry: Bep10Registry,
}

impl<'a> MessageChannel<'a> {
    fn new(
        peer: &'a Peer,
        s: Either<TcpStream, msepe::EncryptedStream>,
        local_registry: Bep10Registry,
    ) -> Self {
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

struct PeerConnection<'a, H> {
    channel: MessageChannel<'a>,
    #[allow(dead_code)]
    extensions: ExtensionSet,
    info_hash: H,
    metadata_size: Option<u32>,
}

impl<H: InfoHashProvider> PeerConnection<'_, H> {
    async fn get_metadata_info(&mut self) -> Result<TorrentInfo<H>, PeerError> {
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
    #[error("peer requires encryption, but encryption is disabled")]
    CantRequireCrypto,
    #[error("could not connect to peer")]
    Connect(#[source] std::io::Error),
    #[error("timed out trying to connect to peer and complete handshake")]
    ConnectTimeout,
    #[error("error sending message to peer")]
    Send(#[source] std::io::Error),
    #[error("error receiving message from peer")]
    Recv(#[source] std::io::Error),
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
    #[error(transparent)]
    CryptoHandshake(#[from] msepe::HandshakeError),
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
    #[error(
        "peer declared total metadata size as {handshake} in extended handshake but as {data} in metadata data message"
    )]
    SizeMismatch { handshake: u32, data: u32 },
    #[error("request for metadata piece {expected} was replied to with message for piece {got}")]
    WrongPiece { expected: u32, got: u32 },
    #[error("request for metadata piece {piece} was rejected")]
    InfoRequestRejected { piece: u32 },
    #[error("peer sent unexpected message: {0}")]
    Unexpected(String),
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub(crate) struct DisplayJson<'a>(&'a Peer);

impl fmt::Display for DisplayJson<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{"host": "{}", "port": {}, "id": "#,
            self.0.address.ip(),
            self.0.address.port()
        )?;
        if let Some(ref pid) = self.0.id {
            f.write_char('"')?;
            for chunk in pid.as_bytes().utf8_chunks() {
                write_json_str(chunk.valid(), f)?;
                if !chunk.invalid().is_empty() {
                    write!(f, "\\ufffd")?;
                }
            }
            f.write_char('"')?;
        } else {
            write!(f, "null")?;
        }
        write!(
            f,
            r#", "requires_crypto": {}}}"#,
            if self.0.requires_crypto {
                "true"
            } else {
                "false"
            }
        )?;
        Ok(())
    }
}

fn write_json_str<W: Write>(s: &str, writer: &mut W) -> fmt::Result {
    for c in s.chars() {
        match c {
            '"' => writer.write_str("\\\"")?,
            '\\' => writer.write_str(r"\\")?,
            '\x08' => writer.write_str("\\b")?,
            '\x0C' => writer.write_str("\\f")?,
            '\n' => writer.write_str("\\n")?,
            '\r' => writer.write_str("\\r")?,
            '\t' => writer.write_str("\\t")?,
            ' '..='~' => writer.write_char(c)?,
            c => {
                let mut buf = [0u16; 2];
                for b in c.encode_utf16(&mut buf) {
                    write!(writer, "\\u{b:04x}")?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{UnbencodeError, decode_bencode};
    use rstest::rstest;

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
        assert_eq!(peer.id, Some(PeerId::from(b"-PRE-123-abcdefghijk")));
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
        assert_eq!(peer.id, Some(PeerId::from(b"-PRE-123-abcdefghijk")));
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

    mod display_json {
        use super::*;

        #[test]
        fn no_id() {
            let peer = "127.0.0.1:8080".parse::<Peer>().unwrap();
            let s = peer.display_json().to_string();
            assert_eq!(
                s,
                r#"{"host": "127.0.0.1", "port": 8080, "id": null, "requires_crypto": false}"#
            );
        }

        #[test]
        fn simple_id() {
            let peer = decode_bencode::<Peer>(
                b"d2:ip9:127.0.0.17:peer id20:-PRE-123-abcdefghijk4:porti8080ee",
            )
            .unwrap();
            let s = peer.display_json().to_string();
            assert_eq!(
                s,
                r#"{"host": "127.0.0.1", "port": 8080, "id": "-PRE-123-abcdefghijk", "requires_crypto": false}"#
            );
        }

        #[test]
        fn non_ascii_id() {
            let peer = decode_bencode::<Peer>(
                b"d2:ip9:127.0.0.17:peer id20:-PRE-123-abcdefgh\xC3\xAEj4:porti8080ee",
            )
            .unwrap();
            let s = peer.display_json().to_string();
            assert_eq!(
                s,
                r#"{"host": "127.0.0.1", "port": 8080, "id": "-PRE-123-abcdefgh\u00eej", "requires_crypto": false}"#
            );
        }

        #[test]
        fn non_utf8_id() {
            let peer = decode_bencode::<Peer>(
                b"d2:ip9:127.0.0.17:peer id20:-PRE-123-abcdefgh\xEEjk4:porti8080ee",
            )
            .unwrap();
            let s = peer.display_json().to_string();
            assert_eq!(
                s,
                r#"{"host": "127.0.0.1", "port": 8080, "id": "-PRE-123-abcdefgh\ufffdjk", "requires_crypto": false}"#
            );
        }

        #[test]
        fn requires_crypto() {
            let peer = Peer {
                address: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
                id: None,
                requires_crypto: true,
            };
            let s = peer.display_json().to_string();
            assert_eq!(
                s,
                r#"{"host": "127.0.0.1", "port": 8080, "id": null, "requires_crypto": true}"#
            );
        }
    }

    #[rstest]
    #[case("foobar", "foobar")]
    #[case("foo / bar", "foo / bar")]
    #[case("foo\"bar", r#"foo\"bar"#)]
    #[case("foo\\bar", r"foo\\bar")]
    #[case("foo\x08\x0C\n\r\tbar", r"foo\b\f\n\r\tbar")]
    #[case("foo\x0B\x1B\x7Fbar", r"foo\u000b\u001b\u007fbar")]
    #[case("foo—bar", r"foo\u2014bar")]
    #[case("foo🐐bar", r"foo\ud83d\udc10bar")]
    fn test_write_json_str(#[case] s: &str, #[case] json: String) {
        let mut buf = String::new();
        write_json_str(s, &mut buf).unwrap();
        assert_eq!(buf, json);
    }
}
