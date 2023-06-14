use super::{Extension, ExtensionSet};
use crate::types::{InfoHash, PeerId};
use crate::util::{PacketError, TryBytes, UnbencodeError};
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::BTreeMap;
use thiserror::Error;

static HANDSHAKE_HEADER: &[u8; 20] = b"\x13BitTorrent protocol";

pub(super) struct Handshake {
    extensions: ExtensionSet,
    info_hash: InfoHash,
    peer_id: PeerId,
}

impl Handshake {
    pub(super) fn new<I>(extensions: I, info_hash: &InfoHash, peer_id: &PeerId) -> Handshake
    where
        I: IntoIterator<Item = Extension>,
    {
        Handshake {
            extensions: extensions.into_iter().collect(),
            info_hash: info_hash.clone(),
            peer_id: peer_id.clone(),
        }
    }
}

impl From<Handshake> for Bytes {
    fn from(shake: Handshake) -> Bytes {
        let mut buf = BytesMut::with_capacity(20 + 8 + 20 + 20);
        buf.put(HANDSHAKE_HEADER.as_slice());
        buf.put_u64(shake.extensions.into());
        buf.put(shake.info_hash.as_bytes());
        buf.put(shake.peer_id.as_bytes());
        buf.freeze()
    }
}

impl TryFrom<Bytes> for Handshake {
    type Error = HandshakeError;

    fn try_from(buf: Bytes) -> Result<Handshake, Self::Error> {
        let mut buf = TryBytes::from(buf);
        let header = buf.try_get_bytes(20)?;
        if header != HANDSHAKE_HEADER.as_slice() {
            return Err(HandshakeError::InvalidHeader);
        }
        let extensions = ExtensionSet::from(buf.try_get::<u64>()?);
        let info_hash = buf.try_get::<InfoHash>()?;
        let peer_id = buf.try_get::<PeerId>()?;
        buf.eof()?;
        Ok(Handshake {
            extensions,
            info_hash,
            peer_id,
        })
    }
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub(super) enum HandshakeError {
    #[error("peer sent handshake with invalid header")]
    InvalidHeader,
    #[error("peer sent handshake with invalid length")]
    Length(#[from] PacketError),
    // TODO: Add "wrong info hash"
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AnyMessage {
    Core(CoreMessage),
    Extended(ExtendedMessage),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CoreMessage {
    // BEP 3:
    Keepalive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have { piece: u32 },
    Bitfield(Bytes),
    Request { index: u32, begin: u32, length: u32 },
    Piece { index: u32, begin: u32, data: Bytes },
    Cancel { index: u32, begin: u32, length: u32 },
    // BEP 5 (DHT):
    Port { port: u16 },
    // BEP 6:
    Suggest { index: u32 },
    HaveAll,
    HaveNone,
    Reject { index: u32, begin: u32, length: u32 },
    AllowedFast { index: u32 },
    // BEP 10:
    Extended { msg_id: u8, payload: Bytes },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ExtendedMessage {
    Handshake(ExtendedHandshake),
    Metadata(MetadataMessage),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExtendedHandshake {
    m: Option<BTreeMap<String, u8>>,
    v: Option<String>,
    metadata_size: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MetadataMessage {
    Request {
        piece: u32,
    },
    Data {
        piece: u32,
        total_size: u32,
        payload: Bytes,
    },
    Reject {
        piece: u32,
    },
}

#[derive(Clone, Debug, Error)]
pub(super) enum MessageError {
    #[error("unknown message type: {0}")]
    Unknown(u8),
    #[error("message had invalid length")]
    // TODO: Should this include information on the kind of message?
    Length(#[from] PacketError),
    #[error("unknown extended message ID: {0}")]
    UnknownExtended(u8),
    #[error("unknown metadata message type: {0}")]
    UnknownMetadata(u32),
    #[error("failed to decode extended handshake payload")]
    ExtendedHandshake(#[source] UnbencodeError),
    #[error("failed to decode metadata message")]
    Metadata(#[source] UnbencodeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_tofrom_bytes() {
        let mut buf = BytesMut::new();
        buf.put(b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10".as_slice());
        buf.put(b"\x00\x05k\xcb\xd4A\xd7\xa0\x88\xc6;\xa8\xf8\x82".as_slice());
        buf.put(b"\xe3\x12\x91\xd3\x85\xa7\x96L-TR3000-vfu1svh0ewb6".as_slice());
        let buf = buf.freeze();
        let shake = Handshake::try_from(buf.clone()).unwrap();
        assert_eq!(
            shake.extensions,
            ExtensionSet::from_iter([Extension::Bep10, Extension::Fast, Extension::Dht])
        );
        assert_eq!(
            shake.info_hash.as_bytes(),
            b"k\xcb\xd4A\xd7\xa0\x88\xc6;\xa8\xf8\x82\xe3\x12\x91\xd3\x85\xa7\x96L"
        );
        assert_eq!(shake.peer_id.as_bytes(), b"-TR3000-vfu1svh0ewb6");
        assert_eq!(Bytes::from(shake), buf);
    }

    #[test]
    fn test_handshake_unknown_ext_tofrom_bytes() {
        let mut buf = BytesMut::new();
        buf.put(b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x18".as_slice());
        buf.put(b"\x00\x05k\xcb\xd4A\xd7\xa0\x88\xc6;\xa8\xf8\x82".as_slice());
        buf.put(b"\xe3\x12\x91\xd3\x85\xa7\x96L-qB4360-5Ngjy9uIMl~O".as_slice());
        let buf = buf.freeze();
        let shake = Handshake::try_from(buf.clone()).unwrap();
        assert_eq!(u64::from(shake.extensions), 0x180005);
        assert_eq!(
            shake.info_hash.as_bytes(),
            b"k\xcb\xd4A\xd7\xa0\x88\xc6;\xa8\xf8\x82\xe3\x12\x91\xd3\x85\xa7\x96L"
        );
        assert_eq!(shake.peer_id.as_bytes(), b"-qB4360-5Ngjy9uIMl~O");
        assert_eq!(Bytes::from(shake), buf);
    }
}
