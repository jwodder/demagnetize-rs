use bytes::Bytes;
use data_encoding::{DecodeError, BASE32, HEXLOWER_PERMISSIVE};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct InfoHash(Bytes);

impl InfoHash {
    pub(crate) fn from_hex(s: &str) -> Result<InfoHash, InfoHashError> {
        let bs = HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .map_err(InfoHashError::InvalidHex)?;
        Bytes::from(bs).try_into()
    }

    pub(crate) fn from_base32(s: &str) -> Result<InfoHash, InfoHashError> {
        let bs = BASE32
            .decode(s.as_bytes())
            .map_err(InfoHashError::InvalidBase32)?;
        Bytes::from(bs).try_into()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
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

impl TryFrom<Bytes> for InfoHash {
    type Error = InfoHashError;

    fn try_from(bs: Bytes) -> Result<InfoHash, InfoHashError> {
        if bs.len() == 20 {
            Ok(InfoHash(bs))
        } else {
            Err(InfoHashError::InvalidLength(bs.len()))
        }
    }
}

#[derive(Debug, Eq, Error, PartialEq)]
pub(crate) enum InfoHashError {
    #[error("info hash is invalid hexadecimal")]
    InvalidHex(#[source] DecodeError),
    #[error("info hash is invalid base32")]
    InvalidBase32(#[from] DecodeError),
    #[error("info hash is {0} bytes long, expected 20")]
    InvalidLength(usize),
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
}
