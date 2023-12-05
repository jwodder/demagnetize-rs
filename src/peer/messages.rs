use super::extensions::{
    Bep10Extension, Bep10Registry, Bep10RegistryError, Extension, ExtensionSet,
};
use crate::types::{InfoHash, PeerId};
use crate::util::{decode_bencode, PacketError, TryBytes, UnbencodeError};
use bendy::decoding::{Decoder, Error as BendyError, FromBencode, Object, ResultExt};
use bendy::encoding::{Encoder, SingleItemEncoder, ToBencode};
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;

static HANDSHAKE_HEADER: &[u8; 20] = b"\x13BitTorrent protocol";

pub(super) struct Handshake {
    pub(super) extensions: ExtensionSet,
    pub(super) info_hash: InfoHash,
    pub(super) peer_id: PeerId,
}

impl Handshake {
    pub(super) const LENGTH: usize = 20 + 8 + 20 + 20;

    pub(super) fn new<I>(extensions: I, info_hash: InfoHash, peer_id: PeerId) -> Handshake
    where
        I: IntoIterator<Item = Extension>,
    {
        Handshake {
            extensions: extensions.into_iter().collect(),
            info_hash,
            peer_id,
        }
    }
}

impl fmt::Display for Handshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "handshake (extensions: {}; peer ID: {})",
            self.extensions, self.peer_id
        )
    }
}

impl From<Handshake> for Bytes {
    fn from(shake: Handshake) -> Bytes {
        let mut buf = BytesMut::with_capacity(Handshake::LENGTH);
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
pub(crate) enum HandshakeError {
    #[error("peer sent handshake with invalid header")]
    InvalidHeader,
    #[error("peer sent handshake with invalid length")]
    Length(#[from] PacketError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Message {
    Core(CoreMessage),
    Extended(ExtendedMessage),
}

impl Message {
    pub(super) fn decode(buf: Bytes, registry: &Bep10Registry) -> Result<Message, MessageError> {
        match CoreMessage::try_from(buf)? {
            CoreMessage::Extended { msg_id, payload } => Ok(Message::Extended(
                ExtendedMessage::decode(msg_id, payload, registry)?,
            )),
            msg => Ok(Message::Core(msg)),
        }
    }

    pub(super) fn encode(self, registry: &Bep10Registry) -> Result<Bytes, MessageEncodeError> {
        match self {
            Message::Core(msg) => Ok(Bytes::from(msg)),
            Message::Extended(msg) => {
                let (msg_id, payload) = msg.encode(registry)?;
                Ok(Bytes::from(CoreMessage::Extended { msg_id, payload }))
            }
        }
    }

    pub(super) fn can_be_ignored(&self) -> bool {
        match self {
            Message::Core(msg) => msg.can_be_ignored(),
            Message::Extended(msg) => msg.can_be_ignored(),
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Message::Core(msg) => write!(f, "{msg}"),
            Message::Extended(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<ExtendedHandshake> for Message {
    fn from(shake: ExtendedHandshake) -> Message {
        Message::Extended(ExtendedMessage::Handshake(shake))
    }
}

impl From<MetadataMessage> for Message {
    fn from(msg: MetadataMessage) -> Message {
        Message::Extended(ExtendedMessage::Metadata(msg))
    }
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

impl CoreMessage {
    fn can_be_ignored(&self) -> bool {
        use CoreMessage::*;
        matches!(
            self,
            Keepalive
                | Choke
                | Unchoke
                | Interested
                | NotInterested
                | Have { .. }
                | Bitfield(_)
                | Piece { .. }
                | HaveAll
                | HaveNone
                | AllowedFast { .. }
                | Suggest { .. }
        )
    }
}

impl fmt::Display for CoreMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreMessage::Keepalive => write!(f, "keepalive"),
            CoreMessage::Choke => write!(f, "choke"),
            CoreMessage::Unchoke => write!(f, "unchoke"),
            CoreMessage::Interested => write!(f, "interested"),
            CoreMessage::NotInterested => write!(f, "not interested"),
            CoreMessage::Have { piece } => write!(f, "have: piece {piece}"),
            CoreMessage::Bitfield(bitfield) => {
                let total = bitfield.iter().copied().map(u8::count_ones).sum::<u32>();
                write!(f, "bitfield: have {total} pieces")
            }
            CoreMessage::Request {
                index,
                begin,
                length,
            } => write!(f, "request: index {index}, begin {begin}, length {length}"),
            CoreMessage::Piece { index, begin, data } => write!(
                f,
                "piece: index {index}, begin {begin}, length {}",
                data.len()
            ),
            CoreMessage::Cancel {
                index,
                begin,
                length,
            } => write!(f, "cancel: index {index}, begin {begin}, length {length}"),
            CoreMessage::Port { port } => write!(f, "DHT port: {port}"),
            CoreMessage::Suggest { index } => write!(f, "suggest: piece {index}"),
            CoreMessage::HaveAll => write!(f, "have all"),
            CoreMessage::HaveNone => write!(f, "have none"),
            CoreMessage::Reject {
                index,
                begin,
                length,
            } => write!(f, "reject: index {index}, begin {begin}, length {length}"),
            CoreMessage::AllowedFast { index } => write!(f, "allowed fast: piece {index}"),
            CoreMessage::Extended { msg_id, .. } => {
                write!(f, "extended message (message ID {msg_id})")
            }
        }
    }
}

impl From<CoreMessage> for Bytes {
    fn from(msg: CoreMessage) -> Bytes {
        // The returned buffer does not include the length prefix, as that is
        // added by LengthDelimitedCodec.
        match msg {
            CoreMessage::Keepalive => Bytes::new(),
            CoreMessage::Choke => Bytes::from(vec![0]),
            CoreMessage::Unchoke => Bytes::from(vec![1]),
            CoreMessage::Interested => Bytes::from(vec![2]),
            CoreMessage::NotInterested => Bytes::from(vec![3]),
            CoreMessage::Have { piece } => {
                let mut buf = BytesMut::with_capacity(5);
                buf.put_u8(4);
                buf.put_u32(piece);
                buf.freeze()
            }
            CoreMessage::Bitfield(bitfield) => {
                let mut buf = BytesMut::with_capacity(1 + bitfield.len());
                buf.put_u8(5);
                buf.extend(bitfield);
                buf.freeze()
            }
            CoreMessage::Request {
                index,
                begin,
                length,
            } => {
                let mut buf = BytesMut::with_capacity(13);
                buf.put_u8(6);
                buf.put_u32(index);
                buf.put_u32(begin);
                buf.put_u32(length);
                buf.freeze()
            }
            CoreMessage::Piece { index, begin, data } => {
                let mut buf = BytesMut::with_capacity(9 + data.len());
                buf.put_u8(7);
                buf.put_u32(index);
                buf.put_u32(begin);
                buf.extend(data);
                buf.freeze()
            }
            CoreMessage::Cancel {
                index,
                begin,
                length,
            } => {
                let mut buf = BytesMut::with_capacity(13);
                buf.put_u8(8);
                buf.put_u32(index);
                buf.put_u32(begin);
                buf.put_u32(length);
                buf.freeze()
            }
            CoreMessage::Port { port } => {
                let mut buf = BytesMut::with_capacity(3);
                buf.put_u8(9);
                buf.put_u16(port);
                buf.freeze()
            }
            CoreMessage::Suggest { index } => {
                let mut buf = BytesMut::with_capacity(5);
                buf.put_u8(0x0D);
                buf.put_u32(index);
                buf.freeze()
            }
            CoreMessage::HaveAll => Bytes::from(vec![0x0E]),
            CoreMessage::HaveNone => Bytes::from(vec![0x0F]),
            CoreMessage::Reject {
                index,
                begin,
                length,
            } => {
                let mut buf = BytesMut::with_capacity(13);
                buf.put_u8(0x10);
                buf.put_u32(index);
                buf.put_u32(begin);
                buf.put_u32(length);
                buf.freeze()
            }
            CoreMessage::AllowedFast { index } => {
                let mut buf = BytesMut::with_capacity(5);
                buf.put_u8(0x11);
                buf.put_u32(index);
                buf.freeze()
            }
            CoreMessage::Extended { msg_id, payload } => {
                let mut buf = BytesMut::with_capacity(2 + payload.len());
                buf.put_u8(0x14);
                buf.put_u8(msg_id);
                buf.extend(payload);
                buf.freeze()
            }
        }
    }
}

impl TryFrom<Bytes> for CoreMessage {
    type Error = MessageError;

    fn try_from(buf: Bytes) -> Result<CoreMessage, MessageError> {
        // `buf` does not include the length prefix, as that is stripped by
        // LengthDelimitedCodec.
        let mut buf = TryBytes::from(buf);
        let Ok(msg_type) = buf.try_get::<u8>() else {
            return Ok(CoreMessage::Keepalive);
        };
        let errmap = &|source| MessageError::Length { msg_type, source };
        match msg_type {
            0 => {
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::Choke)
            }
            1 => {
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::Unchoke)
            }
            2 => {
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::Interested)
            }
            3 => {
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::NotInterested)
            }
            4 => {
                let piece = buf.try_get::<u32>().map_err(errmap)?;
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::Have { piece })
            }
            5 => Ok(CoreMessage::Bitfield(buf.remainder())),
            6 => {
                let index = buf.try_get::<u32>().map_err(errmap)?;
                let begin = buf.try_get::<u32>().map_err(errmap)?;
                let length = buf.try_get::<u32>().map_err(errmap)?;
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::Request {
                    index,
                    begin,
                    length,
                })
            }
            7 => {
                let index = buf.try_get::<u32>().map_err(errmap)?;
                let begin = buf.try_get::<u32>().map_err(errmap)?;
                let data = buf.remainder();
                Ok(CoreMessage::Piece { index, begin, data })
            }
            8 => {
                let index = buf.try_get::<u32>().map_err(errmap)?;
                let begin = buf.try_get::<u32>().map_err(errmap)?;
                let length = buf.try_get::<u32>().map_err(errmap)?;
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::Cancel {
                    index,
                    begin,
                    length,
                })
            }
            9 => {
                let port = buf.try_get::<u16>().map_err(errmap)?;
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::Port { port })
            }
            0x0D => {
                let index = buf.try_get::<u32>().map_err(errmap)?;
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::Suggest { index })
            }
            0x0E => {
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::HaveAll)
            }
            0x0F => {
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::HaveNone)
            }
            0x10 => {
                let index = buf.try_get::<u32>().map_err(errmap)?;
                let begin = buf.try_get::<u32>().map_err(errmap)?;
                let length = buf.try_get::<u32>().map_err(errmap)?;
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::Reject {
                    index,
                    begin,
                    length,
                })
            }
            0x11 => {
                let index = buf.try_get::<u32>().map_err(errmap)?;
                buf.eof().map_err(errmap)?;
                Ok(CoreMessage::AllowedFast { index })
            }
            0x14 => {
                let msg_id = buf.try_get::<u8>().map_err(errmap)?;
                let payload = buf.remainder();
                Ok(CoreMessage::Extended { msg_id, payload })
            }
            x => Err(MessageError::Unknown(x)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ExtendedMessage {
    Handshake(ExtendedHandshake),
    Metadata(MetadataMessage),
}

impl ExtendedMessage {
    fn decode(
        msg_id: u8,
        payload: Bytes,
        registry: &Bep10Registry,
    ) -> Result<ExtendedMessage, MessageError> {
        if msg_id == 0 {
            return Ok(ExtendedMessage::Handshake(ExtendedHandshake::try_from(
                payload,
            )?));
        }
        let Some(ext) = registry.for_message_id(msg_id) else {
            return Err(MessageError::UnknownExtended(msg_id));
        };
        match ext {
            Bep10Extension::Metadata => Ok(ExtendedMessage::Metadata(MetadataMessage::try_from(
                payload,
            )?)),
        }
    }

    fn encode(self, registry: &Bep10Registry) -> Result<(u8, Bytes), MessageEncodeError> {
        match self {
            ExtendedMessage::Handshake(shake) => Ok((0, Bytes::from(shake))),
            ExtendedMessage::Metadata(msg) => {
                let Some(msg_id) = registry.get_message_id(Bep10Extension::Metadata) else {
                    return Err(MessageEncodeError(Bep10Extension::Metadata));
                };
                let payload = Bytes::from(msg);
                Ok((msg_id, payload))
            }
        }
    }

    fn can_be_ignored(&self) -> bool {
        match self {
            // It's valid for a peer to send an extended handshake more than
            // once, and it's valid for us to ignore subsequent handshakes, so
            // that's what we'll do.
            ExtendedMessage::Handshake(_) => true,
            ExtendedMessage::Metadata(msg) => msg.can_be_ignored(),
        }
    }
}

impl fmt::Display for ExtendedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtendedMessage::Handshake(msg) => write!(f, "{msg}"),
            ExtendedMessage::Metadata(msg) => write!(f, "{msg}"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ExtendedHandshake {
    pub(super) m: Option<BTreeMap<String, u8>>,
    pub(super) v: Option<String>,
    pub(super) metadata_size: Option<u32>,
}

impl ExtendedHandshake {
    pub(super) fn into_bep10_registry(self) -> Result<Bep10Registry, Bep10RegistryError> {
        match self.m {
            Some(m) => Bep10Registry::from_m(m),
            None => Ok(Bep10Registry::new()),
        }
    }
}

impl fmt::Display for ExtendedHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "extended handshake: ")?;
        if let Some(m) = self.m.as_ref() {
            write!(f, "extensions: ")?;
            let mut first = true;
            for k in m.keys() {
                if !std::mem::replace(&mut first, false) {
                    write!(f, ", ")?;
                }
                write!(f, "{k:?}")?;
            }
            if first {
                write!(f, "<none>")?;
            }
        } else {
            write!(f, "no extensions")?;
        }
        if let Some(v) = self.v.as_ref() {
            write!(f, "; client: {v:?}")?;
        }
        if let Some(metadata_size) = self.metadata_size {
            write!(f, "; metadata size: {metadata_size:?}")?;
        }
        Ok(())
    }
}

impl From<ExtendedHandshake> for Bytes {
    fn from(eshake: ExtendedHandshake) -> Bytes {
        Bytes::from(eshake.to_bencode().expect("Bencoding should not fail"))
    }
}

impl TryFrom<Bytes> for ExtendedHandshake {
    type Error = MessageError;

    fn try_from(buf: Bytes) -> Result<ExtendedHandshake, MessageError> {
        decode_bencode(&buf).map_err(MessageError::ExtendedHandshake)
    }
}

impl ToBencode for ExtendedHandshake {
    const MAX_DEPTH: usize = 3;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            if let Some(m) = self.m.as_ref() {
                e.emit_pair(b"m", m)?;
            }
            if let Some(metadata_size) = self.metadata_size {
                e.emit_pair(b"metadata_size", metadata_size)?;
            }
            if let Some(v) = self.v.as_ref() {
                e.emit_pair(b"v", v)?;
            }
            Ok(())
        })
    }
}

impl FromBencode for ExtendedHandshake {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<ExtendedHandshake, BendyError> {
        let mut m = None;
        let mut v = None;
        let mut metadata_size = None;
        let mut dd = object.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            match kv {
                (b"m", value) => {
                    m = Some(BTreeMap::<String, u8>::decode_bencode_object(value).context("m")?);
                }
                (b"v", value) => {
                    v = Some(String::decode_bencode_object(value).context("v")?);
                }
                (b"metadata_size", value) => {
                    metadata_size =
                        Some(u32::decode_bencode_object(value).context("metadata_size")?);
                }
                _ => (),
            }
        }
        Ok(ExtendedHandshake {
            m,
            v,
            metadata_size,
        })
    }
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
    // To be ignored on receipt, per BEP 9; not sent
    Unknown {
        msg_type: u8,
    },
}

impl MetadataMessage {
    fn can_be_ignored(&self) -> bool {
        matches!(self, MetadataMessage::Unknown { .. })
    }
}

impl fmt::Display for MetadataMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetadataMessage::Request { piece } => write!(f, "metadata request: piece {piece}"),
            MetadataMessage::Data {
                piece,
                total_size,
                payload,
            } => write!(
                f,
                "metadata data: piece {piece}, total size {total_size}, payload size {}",
                payload.len()
            ),
            MetadataMessage::Reject { piece } => write!(f, "metadata reject: piece {piece}"),
            MetadataMessage::Unknown { msg_type } => {
                write!(f, "metadata: unknown message type {msg_type}")
            }
        }
    }
}

impl From<MetadataMessage> for Bytes {
    fn from(msg: MetadataMessage) -> Bytes {
        let mut encoder = Encoder::new().with_max_depth(3);
        encoder
            .emit_dict(|mut e| {
                match msg {
                    MetadataMessage::Request { piece } => {
                        e.emit_pair(b"msg_type", 0)?;
                        e.emit_pair(b"piece", piece)?;
                    }
                    MetadataMessage::Data {
                        piece, total_size, ..
                    } => {
                        e.emit_pair(b"msg_type", 1)?;
                        e.emit_pair(b"piece", piece)?;
                        e.emit_pair(b"total_size", total_size)?;
                    }
                    MetadataMessage::Reject { piece } => {
                        e.emit_pair(b"msg_type", 2)?;
                        e.emit_pair(b"piece", piece)?;
                    }
                    MetadataMessage::Unknown { msg_type } => {
                        e.emit_pair(b"msg_type", msg_type)?;
                    }
                }
                Ok(())
            })
            .expect("Encoding should not fail");
        let mut buf = encoder.get_output().expect("Encoding should not fail");
        if let MetadataMessage::Data { payload, .. } = msg {
            buf.extend(payload);
        }
        Bytes::from(buf)
    }
}

impl TryFrom<Bytes> for MetadataMessage {
    type Error = MessageError;

    fn try_from(mut buf: Bytes) -> Result<MetadataMessage, MessageError> {
        let mut decoder = Decoder::new(&buf).with_max_depth(2);
        let mut dd = match decoder.next_object() {
            Ok(Some(obj)) => match obj.try_into_dictionary() {
                Ok(dd) => dd,
                Err(e) => return Err(MessageError::metadata_bendy(e)),
            },
            Ok(None) => return Err(MessageError::Metadata(UnbencodeError::NoData)),
            Err(e) => return Err(MessageError::metadata_bendy(e)),
        };
        let mut msg_type = None;
        let mut piece = None;
        let mut total_size = None;
        while let Some(kv) = dd.next_pair().map_err(MessageError::metadata_bendy)? {
            match kv {
                (b"msg_type", v) => {
                    msg_type = Some(
                        u8::decode_bencode_object(v)
                            .context("msg_type")
                            .map_err(MessageError::metadata_bendy)?,
                    );
                }
                (b"piece", v) => {
                    piece = Some(
                        u32::decode_bencode_object(v)
                            .context("piece")
                            .map_err(MessageError::metadata_bendy)?,
                    );
                }
                (b"total_size", v) => {
                    total_size = Some(
                        u32::decode_bencode_object(v)
                            .context("total_size")
                            .map_err(MessageError::metadata_bendy)?,
                    );
                }
                _ => (),
            }
        }
        let Some(msg_type) = msg_type else {
            return Err(MessageError::metadata_bendy(BendyError::missing_field(
                "msg_type",
            )));
        };
        let Some(piece) = piece else {
            return Err(MessageError::metadata_bendy(BendyError::missing_field(
                "piece",
            )));
        };
        let dict_len = dd
            .into_raw()
            .expect("should not fail after consuming all pairs in dictionary")
            .len();
        match msg_type {
            0 => {
                if !matches!(decoder.next_object(), Ok(None)) {
                    return Err(MessageError::Metadata(UnbencodeError::TrailingData));
                }
                Ok(MetadataMessage::Request { piece })
            }
            1 => {
                let Some(total_size) = total_size else {
                    return Err(MessageError::metadata_bendy(BendyError::missing_field(
                        "total_size",
                    )));
                };
                let payload = buf.split_off(dict_len);
                Ok(MetadataMessage::Data {
                    piece,
                    total_size,
                    payload,
                })
            }
            2 => {
                if !matches!(decoder.next_object(), Ok(None)) {
                    return Err(MessageError::Metadata(UnbencodeError::TrailingData));
                }
                Ok(MetadataMessage::Reject { piece })
            }
            _ => Ok(MetadataMessage::Unknown { msg_type }),
        }
    }
}

#[derive(Clone, Debug, Error)]
pub(crate) enum MessageError {
    #[error("unknown message type: {0}")]
    Unknown(u8),
    #[error("message type {msg_type:#4x} had invalid length")]
    Length { msg_type: u8, source: PacketError },
    #[error("unknown extended message ID: {0}")]
    UnknownExtended(u8),
    #[error("failed to decode extended handshake payload")]
    ExtendedHandshake(#[source] UnbencodeError),
    #[error("failed to decode metadata message")]
    Metadata(#[source] UnbencodeError),
}

impl MessageError {
    fn metadata_bendy(e: BendyError) -> MessageError {
        MessageError::Metadata(UnbencodeError::Bendy(e))
    }
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
#[error("no remote message ID registered for extension \"{0}\"")]
pub(super) struct MessageEncodeError(Bep10Extension);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake() {
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
        assert_eq!(shake.to_string(), "handshake (extensions: BEP 10 Extension Protocol, BitTorrent DHT, Fast Extension; peer ID: b\"-TR3000-vfu1svh0ewb6\")");
        assert_eq!(Bytes::from(shake), buf);
    }

    #[test]
    fn test_handshake_unknown_ext() {
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
        assert_eq!(shake.to_string(), "handshake (extensions: BEP 10 Extension Protocol, BitTorrent DHT, Fast Extension, Unknown(0x0000000000080000); peer ID: b\"-qB4360-5Ngjy9uIMl~O\")");
        assert_eq!(Bytes::from(shake), buf);
    }

    #[test]
    fn test_haveall() {
        let buf = Bytes::from(b"\x0E".as_slice());
        assert_eq!(
            CoreMessage::try_from(buf.clone()).unwrap(),
            CoreMessage::HaveAll
        );
        assert_eq!(CoreMessage::HaveAll.to_string(), "have all");
        assert_eq!(Bytes::from(CoreMessage::HaveAll), buf);
    }

    #[test]
    fn test_havenone() {
        let buf = Bytes::from(b"\x0F".as_slice());
        assert_eq!(
            CoreMessage::try_from(buf.clone()).unwrap(),
            CoreMessage::HaveNone
        );
        assert_eq!(CoreMessage::HaveNone.to_string(), "have none");
        assert_eq!(Bytes::from(CoreMessage::HaveNone), buf);
    }

    #[test]
    fn test_port() {
        let buf = Bytes::from(b"\x09\x88\xB7".as_slice());
        assert_eq!(
            CoreMessage::try_from(buf.clone()).unwrap(),
            CoreMessage::Port { port: 34999 }
        );
        assert_eq!(
            (CoreMessage::Port { port: 34999 }).to_string(),
            "DHT port: 34999"
        );
        assert_eq!(Bytes::from(CoreMessage::Port { port: 34999 }), buf);
    }

    #[test]
    fn test_extended() {
        // ut_pex
        let buf = Bytes::from(
            b"\x14\x01d5:added12:V`\\\xe5\xc8\xd5\xb2\x9b\x8b\xa8\x88\xb77:added.f2:\x10\x10e"
                .as_slice(),
        );
        let msg = CoreMessage::Extended {
            msg_id: 1,
            payload: Bytes::from(
                b"d5:added12:V`\\\xe5\xc8\xd5\xb2\x9b\x8b\xa8\x88\xb77:added.f2:\x10\x10e"
                    .as_slice(),
            ),
        };
        assert_eq!(CoreMessage::try_from(buf.clone()).unwrap(), msg);
        assert_eq!(msg.to_string(), "extended message (message ID 1)");
        assert_eq!(Bytes::from(msg), buf);
    }

    #[test]
    fn test_decode_extended_handshake() {
        let registry = Bep10Registry::new();
        let mut buf = BytesMut::new();
        buf.put(b"\x14\x00d12:complete_agoi1441e1:".as_slice());
        buf.put(b"md11:lt_donthavei7e10:share_modei8e11:upload_onl".as_slice());
        buf.put(b"yi3e12:ut_holepunchi4e11:ut_metadatai2e6:ut_pexi".as_slice());
        buf.put(b"1ee13:metadata_sizei5436e4:reqqi500e11:upload_on".as_slice());
        buf.put(b"lyi1e1:v17:qBittorrent/4.3.66:yourip4:\x99\xa2D".as_slice());
        buf.put(b"\x9be".as_slice());
        let buf = buf.freeze();
        let msg = Message::decode(buf, &registry).unwrap();
        assert_eq!(
            msg,
            Message::from(ExtendedHandshake {
                m: Some(BTreeMap::from([
                    ("lt_donthave".into(), 7),
                    ("share_mode".into(), 8),
                    ("upload_only".into(), 3),
                    ("ut_holepunch".into(), 4),
                    ("ut_metadata".into(), 2),
                    ("ut_pex".into(), 1),
                ])),
                v: Some("qBittorrent/4.3.6".into()),
                metadata_size: Some(5436),
            })
        );
        assert_eq!(msg.to_string(), "extended handshake: extensions: \"lt_donthave\", \"share_mode\", \"upload_only\", \"ut_holepunch\", \"ut_metadata\", \"ut_pex\"; client: \"qBittorrent/4.3.6\"; metadata size: 5436");
        let Message::Extended(ExtendedMessage::Handshake(msg)) = msg else {
            unreachable!();
        };
        let mut their_registry = Bep10Registry::new();
        their_registry
            .register(Bep10Extension::Metadata, 2)
            .unwrap();
        assert_eq!(msg.into_bep10_registry(), Ok(their_registry));
    }

    #[test]
    fn test_encode_extended_handshake() {
        let mut registry = Bep10Registry::new();
        registry.register(Bep10Extension::Metadata, 23).unwrap();
        let msg = Message::from(ExtendedHandshake {
            m: Some(registry.to_m()),
            v: Some("omicron-torrent v1.2.3".into()),
            metadata_size: None,
        });
        let buf = Bytes::from(
            b"\x14\x00d1:md11:ut_metadatai23ee1:v22:omicron-torrent v1.2.3e".as_slice(),
        );
        assert_eq!(msg.encode(&Bep10Registry::new()).unwrap(), buf);
    }

    #[test]
    fn test_metadata_request() {
        let mut registry = Bep10Registry::new();
        registry.register(Bep10Extension::Metadata, 3).unwrap();
        let buf = Bytes::from(b"\x14\x03d8:msg_typei0e5:piecei0ee".as_slice());
        let msg = Message::decode(buf.clone(), &registry).unwrap();
        assert_eq!(msg, Message::from(MetadataMessage::Request { piece: 0 }));
        assert_eq!(msg.to_string(), "metadata request: piece 0");
        assert_eq!(msg.encode(&registry).unwrap(), buf);
    }

    #[test]
    fn test_metadata_data() {
        let mut registry = Bep10Registry::new();
        registry.register(Bep10Extension::Metadata, 3).unwrap();
        let buf = Bytes::from(b"\x14\x03d8:msg_typei1e5:piecei0e10:total_sizei5436eed5:filesld6:lengthi267661684e4:pathl72:...".as_slice());
        let msg = Message::decode(buf.clone(), &registry).unwrap();
        assert_eq!(
            msg,
            Message::from(MetadataMessage::Data {
                piece: 0,
                total_size: 5436,
                payload: Bytes::from(b"d5:filesld6:lengthi267661684e4:pathl72:...".as_slice())
            })
        );
        assert_eq!(
            msg.to_string(),
            "metadata data: piece 0, total size 5436, payload size 42"
        );
        assert_eq!(msg.encode(&registry).unwrap(), buf);
    }
}
