use crate::consts::PEER_ID_PREFIX;
use crate::tracker::{Tracker, TrackerUrlError};
use crate::util::{PacketError, TryFromBuf};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use data_encoding::{DecodeError, BASE32, HEXLOWER_PERMISSIVE};
use rand::Rng;
use rand_distr::{Alphanumeric, Distribution, Standard};
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use url::Url;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct InfoHash(Bytes);

impl InfoHash {
    const LENGTH: usize = 20;

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

    pub(crate) fn add_query_param(&self, url: &mut Url) {
        add_bytes_query_param(url, "info_hash", &self.0);
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
        if bs.len() == InfoHash::LENGTH {
            Ok(InfoHash(bs))
        } else {
            Err(InfoHashError::InvalidLength(bs.len()))
        }
    }
}

impl TryFromBuf for InfoHash {
    fn try_from_buf(buf: &mut Bytes) -> Result<InfoHash, PacketError> {
        if buf.len() >= InfoHash::LENGTH {
            let data = buf.copy_to_bytes(InfoHash::LENGTH);
            debug_assert_eq!(data.len(), InfoHash::LENGTH);
            Ok(InfoHash::try_from(data).expect("Info hash size should be 20"))
        } else {
            Err(PacketError::Short)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalPeer {
    pub id: PeerId,
    pub key: Key,
    pub port: u16,
}

impl LocalPeer {
    pub(crate) fn generate<R: Rng>(mut rng: R) -> LocalPeer {
        let id = PeerId::generate(PEER_ID_PREFIX, &mut rng);
        let key = rng.gen::<Key>();
        let port = rng.gen_range::<u16, _>(1025..=65535);
        LocalPeer { id, key, port }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeerId(Bytes);

impl PeerId {
    const LENGTH: usize = 20;

    pub(crate) fn generate<R: Rng>(prefix: &str, rng: R) -> PeerId {
        let mut bs = prefix.as_bytes();
        if bs.len() > PeerId::LENGTH {
            bs = &bs[..PeerId::LENGTH];
        }
        let mut buf = BytesMut::with_capacity(PeerId::LENGTH);
        buf.extend_from_slice(bs);
        let needed = PeerId::LENGTH.saturating_sub(buf.len());
        if needed > 0 {
            for b in Alphanumeric.sample_iter(rng).take(needed) {
                buf.put_u8(b);
            }
        }
        debug_assert_eq!(buf.len(), PeerId::LENGTH);
        PeerId(buf.freeze())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub(crate) fn add_query_param(&self, url: &mut Url) {
        add_bytes_query_param(url, "peer_id", &self.0);
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl TryFrom<Bytes> for PeerId {
    type Error = PeerIdError;

    fn try_from(bs: Bytes) -> Result<PeerId, PeerIdError> {
        if bs.len() == PeerId::LENGTH {
            Ok(PeerId(bs))
        } else {
            Err(PeerIdError(bs.len()))
        }
    }
}

impl TryFromBuf for PeerId {
    fn try_from_buf(buf: &mut Bytes) -> Result<PeerId, PacketError> {
        if buf.len() >= PeerId::LENGTH {
            let data = buf.copy_to_bytes(PeerId::LENGTH);
            debug_assert_eq!(data.len(), PeerId::LENGTH);
            Ok(PeerId::try_from(data).expect("Peer ID size should be 20"))
        } else {
            Err(PacketError::Short)
        }
    }
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
#[error(
    "invalid length for peer id: expected {} bytes, got {0}",
    PeerId::LENGTH
)]
pub(crate) struct PeerIdError(usize);

/// Key used by client to identify itself to a tracker across requests
///
/// Generate a random Key with `rng.gen::<Key>()`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Key(u32);

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

impl Distribution<Key> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Key {
        Key(Standard.sample(rng))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Magnet {
    info_hash: InfoHash,
    display_name: Option<String>,
    trackers: Vec<Tracker>,
}

impl Magnet {
    fn info_hash(&self) -> &InfoHash {
        &self.info_hash
    }

    fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    fn trackers(&self) -> &[Tracker] {
        &self.trackers
    }
}

impl FromStr for Magnet {
    type Err = MagnetError;

    fn from_str(s: &str) -> Result<Magnet, MagnetError> {
        let url = Url::parse(s)?;
        if url.scheme() != "magnet" {
            return Err(MagnetError::NotMagnet);
        }
        let mut info_hash = None;
        let mut dn = None;
        let mut trackers = Vec::new();
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "xt" => {
                    if info_hash.is_none() {
                        info_hash = Some(parse_xt(&v)?);
                    } else {
                        return Err(MagnetError::MultipleXt);
                    }
                }
                "dn" => {
                    let _ = dn.insert(v);
                }
                "tr" => trackers.push(v.parse::<Tracker>()?),
                _ => (),
            }
        }
        let Some(info_hash) = info_hash else {
            return Err(MagnetError::NoXt);
        };
        if trackers.is_empty() {
            return Err(MagnetError::NoTrackers);
        }
        Ok(Magnet {
            info_hash,
            display_name: dn.map(String::from),
            trackers,
        })
    }
}

#[derive(Debug, Eq, Error, PartialEq)]
pub(crate) enum MagnetError {
    #[error("invalid magnet URI")]
    Url(#[from] url::ParseError),
    #[error("not a magnet URI")]
    NotMagnet,
    #[error("magnet URI lacks \"xt\" parameter")]
    NoXt,
    #[error("invalid \"xt\" parameter")]
    InvalidXt(#[from] XtError),
    #[error("magnet URI has multiple \"xt\" parameters")]
    MultipleXt,
    #[error("no trackers given in magnet URI")]
    NoTrackers,
    #[error("invalid \"tr\" parameter")]
    InvalidTracker(#[from] TrackerUrlError),
}

fn parse_xt(xt: &str) -> Result<InfoHash, XtError> {
    let Some(s) = xt.strip_prefix("urn:") else {
        return Err(XtError::NotUrn);
    };
    let Some(s) = s.strip_prefix("btih:") else {
        return Err(XtError::NotBtih);
    };
    Ok(s.parse::<InfoHash>()?)
}

#[derive(Debug, Eq, Error, PartialEq)]
pub(crate) enum XtError {
    #[error("\"xt\" parameter is not a URN")]
    NotUrn,
    #[error("\"xt\" parameter is not in the \"btih\" namespace")]
    NotBtih,
    #[error("\"xt\" parameter contains invalid info hash")]
    InfoHash(#[from] InfoHashError),
}

fn add_bytes_query_param(url: &mut Url, key: &str, value: &Bytes) {
    static SENTINEL: &str = "ADD_BYTES_QUERY_PARAM";
    url.query_pairs_mut()
        .encoding_override(Some(&|s| {
            if s == SENTINEL {
                Cow::from(Vec::<u8>::from(value.clone()))
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
        assert_eq!(url.as_str(), "http://tracker.example.com:8080/announce?here=there&info_hash=%28%C5Q%96%F5wS%C4%0A%CE%B6%FBXa%7Ei%95%A7%ED%DB")
    }

    #[test]
    fn test_parse_magnet() {
        let magnet = "magnet:?xt=urn:btih:28c55196f57753c40aceb6fb58617e6995a7eddb&dn=debian-11.2.0-amd64-netinst.iso&tr=http%3A%2F%2Fbttracker.debian.org%3A6969%2Fannounce".parse::<Magnet>().unwrap();
        assert_eq!(
            magnet.info_hash().as_bytes(),
            b"\x28\xC5\x51\x96\xF5\x77\x53\xC4\x0A\xCE\xB6\xFB\x58\x61\x7E\x69\x95\xA7\xED\xDB"
        );
        assert_eq!(
            magnet.display_name(),
            Some("debian-11.2.0-amd64-netinst.iso")
        );
        assert_eq!(
            magnet.trackers(),
            ["http://bttracker.debian.org:6969/announce"
                .parse::<Tracker>()
                .unwrap()]
        );
    }

    #[test]
    fn test_generate_peer_id() {
        let peer_id = PeerId::generate("-PRE-123-", rand::thread_rng());
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
        let peer_id = PeerId::generate("-PRE-123-abcdefghijé-", rand::thread_rng());
        assert_eq!(peer_id.as_bytes(), b"-PRE-123-abcdefghij\xC3");
        assert_eq!(peer_id.to_string(), "b\"-PRE-123-abcdefghij\\xc3\"");
    }
}
