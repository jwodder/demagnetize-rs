use crate::util::{PacketError, TryFromBuf};
use bendy::encoding::{SingleItemEncoder, ToBencode};
use bytes::{Buf, Bytes};
use data_encoding::{BASE32, DecodeError, HEXLOWER_PERMISSIVE};
use rand::{
    Rng,
    distr::{Alphanumeric, Distribution, StandardUniform},
};
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use url::Url;

// Used so that a `Magnet` or `Arc<Magnet>` can be passed where an `InfoHash`
// is needed while still outputting the `Magnet` name (if any) in the `Display`
// impl
pub(crate) trait InfoHashProvider: Clone + Send + Sync + fmt::Display {
    fn get_info_hash(&self) -> InfoHash;
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct InfoHash([u8; InfoHash::LENGTH]);

impl InfoHash {
    pub(crate) const LENGTH: usize = 20;

    pub(crate) fn from_hex(s: &str) -> Result<InfoHash, InfoHashError> {
        HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .map_err(InfoHashError::InvalidHex)?
            .try_into()
    }

    pub(crate) fn from_base32(s: &str) -> Result<InfoHash, InfoHashError> {
        BASE32
            .decode(s.as_bytes())
            .map_err(InfoHashError::InvalidBase32)?
            .try_into()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn add_query_param(&self, url: &mut Url) {
        add_bytes_query_param(url, "info_hash", &self.0);
    }
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for InfoHash {
    type Err = InfoHashError;

    fn from_str(s: &str) -> Result<InfoHash, InfoHashError> {
        if s.len() == 32 {
            InfoHash::from_base32(s)
        } else {
            InfoHash::from_hex(s)
        }
    }
}

impl From<&[u8; 20]> for InfoHash {
    fn from(value: &[u8; 20]) -> InfoHash {
        InfoHash(*value)
    }
}

impl TryFrom<Vec<u8>> for InfoHash {
    type Error = InfoHashError;

    fn try_from(bs: Vec<u8>) -> Result<InfoHash, InfoHashError> {
        match bs.try_into() {
            Ok(barray) => Ok(InfoHash(barray)),
            Err(bs) => Err(InfoHashError::InvalidLength(bs.len())),
        }
    }
}

impl TryFromBuf for InfoHash {
    fn try_from_buf(buf: &mut Bytes) -> Result<InfoHash, PacketError> {
        if buf.len() >= InfoHash::LENGTH {
            let mut data = [0u8; InfoHash::LENGTH];
            buf.copy_to_slice(&mut data);
            Ok(InfoHash(data))
        } else {
            Err(PacketError::Short)
        }
    }
}

impl InfoHashProvider for InfoHash {
    fn get_info_hash(&self) -> InfoHash {
        *self
    }
}

impl ToBencode for InfoHash {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        encoder.emit_bytes(&self.0)
    }
}

#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum InfoHashError {
    #[error("info hash is invalid hexadecimal")]
    InvalidHex(#[source] DecodeError),
    #[error("info hash is invalid base32")]
    InvalidBase32(#[source] DecodeError),
    #[error("info hash is {0} bytes long, expected 20")]
    InvalidLength(usize),
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub(crate) struct PeerId([u8; PeerId::LENGTH]);

impl PeerId {
    const LENGTH: usize = 20;

    pub(crate) fn generate<R: Rng>(prefix: &str, rng: &mut R) -> PeerId {
        let bs = prefix.as_bytes();
        PeerId(std::array::from_fn(|i| {
            bs.get(i)
                .copied()
                .unwrap_or_else(|| Alphanumeric.sample(rng))
        }))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub(crate) fn add_query_param(&self, url: &mut Url) {
        add_bytes_query_param(url, "peer_id", &self.0);
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", Bytes::from(self.0.to_vec()))
    }
}

impl From<&[u8; 20]> for PeerId {
    fn from(bs: &[u8; 20]) -> PeerId {
        PeerId(*bs)
    }
}

impl TryFrom<&[u8]> for PeerId {
    type Error = PeerIdError;

    fn try_from(bs: &[u8]) -> Result<PeerId, PeerIdError> {
        match bs.try_into() {
            Ok(barray) => Ok(PeerId(barray)),
            Err(_) => Err(PeerIdError(bs.len())),
        }
    }
}

impl TryFrom<Vec<u8>> for PeerId {
    type Error = PeerIdError;

    fn try_from(bs: Vec<u8>) -> Result<PeerId, PeerIdError> {
        match bs.try_into() {
            Ok(barray) => Ok(PeerId(barray)),
            Err(bs) => Err(PeerIdError(bs.len())),
        }
    }
}

impl TryFromBuf for PeerId {
    fn try_from_buf(buf: &mut Bytes) -> Result<PeerId, PacketError> {
        if buf.len() >= PeerId::LENGTH {
            let mut data = [0u8; PeerId::LENGTH];
            buf.copy_to_slice(&mut data);
            Ok(PeerId(data))
        } else {
            Err(PacketError::Short)
        }
    }
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
#[error(
    "invalid length for peer id: expected {len} bytes, got {0}",
    len = PeerId::LENGTH
)]
pub(crate) struct PeerIdError(usize);

/// Key used by client to identify itself to a tracker across requests
///
/// Generate a random Key with `rng.gen::<Key>()`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Key(u32);

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Key {
    fn from(key: u32) -> Key {
        Key(key)
    }
}

impl From<Key> for u32 {
    fn from(key: Key) -> u32 {
        key.0
    }
}

impl Distribution<Key> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Key {
        Key(StandardUniform.sample(rng))
    }
}

fn add_bytes_query_param(url: &mut Url, key: &str, value: &[u8]) {
    static SENTINEL: &str = "ADD_BYTES_QUERY_PARAM";
    url.query_pairs_mut()
        .encoding_override(Some(&|s| {
            if s == SENTINEL {
                Cow::from(value.to_vec())
            } else {
                Cow::from(s.as_bytes())
            }
        }))
        .append_pair(key, SENTINEL)
        .encoding_override(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_info_hash() {
        let info_hash = "28C55196F57753C40ACEB6FB58617E6995A7EDDB"
            .parse::<InfoHash>()
            .unwrap();
        assert_eq!(
            info_hash.as_bytes(),
            b"\x28\xC5\x51\x96\xF5\x77\x53\xC4\x0A\xCE\xB6\xFB\x58\x61\x7E\x69\x95\xA7\xED\xDB"
        );
        assert_eq!(
            info_hash.to_string(),
            "28c55196f57753c40aceb6fb58617e6995a7eddb"
        );
    }

    #[test]
    fn test_base32_info_hash() {
        let info_hash = "XBIUOS3U6ZONDH4YDRZDLEHD4UQCIK4X"
            .parse::<InfoHash>()
            .unwrap();
        assert_eq!(
            info_hash.as_bytes(),
            b"\xb8\x51\x47\x4b\x74\xf6\x5c\xd1\x9f\x98\x1c\x72\x35\x90\xe3\xe5\x20\x24\x2b\x97",
        );
        assert_eq!(
            info_hash.to_string(),
            "b851474b74f65cd19f981c723590e3e520242b97"
        );
    }

    #[test]
    fn test_add_query_param() {
        let info_hash = "28C55196F57753C40ACEB6FB58617E6995A7EDDB"
            .parse::<InfoHash>()
            .unwrap();
        let mut url = Url::parse("http://tracker.example.com:8080/announce?here=there").unwrap();
        info_hash.add_query_param(&mut url);
        assert_eq!(
            url.as_str(),
            "http://tracker.example.com:8080/announce?here=there&info_hash=%28%C5Q%96%F5wS%C4%0A%CE%B6%FBXa%7Ei%95%A7%ED%DB"
        );
    }

    #[test]
    fn test_generate_peer_id() {
        let peer_id = PeerId::generate("-PRE-123-", &mut rand::rng());
        assert_eq!(peer_id.as_bytes().len(), 20);
        let s = std::str::from_utf8(peer_id.as_bytes()).unwrap();
        let suffix = s.strip_prefix("-PRE-123-").unwrap();
        for ch in suffix.chars() {
            assert!(ch.is_ascii_alphanumeric());
        }
        assert_eq!(peer_id.to_string(), format!("b{s:?}"));
    }

    #[test]
    fn test_generate_peer_id_long_prefix() {
        let peer_id = PeerId::generate("-PRE-123-abcdefghijé-", &mut rand::rng());
        assert_eq!(peer_id.as_bytes(), b"-PRE-123-abcdefghij\xC3");
        assert_eq!(peer_id.to_string(), "b\"-PRE-123-abcdefghij\\xc3\"");
    }
}
