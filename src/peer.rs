mod messages;
use crate::types::PeerId;
use bendy::decoding::{Error as BendyError, FromBencode, Object, ResultExt};
use bytes::Bytes;
use std::fmt;
use std::net::{AddrParseError, IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Peer {
    address: SocketAddr,
    id: Option<PeerId>,
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

#[derive(Copy, Clone, Debug, EnumIter, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum Extension {
    AzureusMessaging = 63, // byte 0, 0x80 (BEP 4)
    LocationAware = 43,    // byte 2, 0x08 (BEP 4)
    Bep10 = 20,            // byte 5, 0x10 (BEP 10)
    Dht = 0,               // byte 7, 0x01 (BEP 4, BEP 5)
    XbtPex = 1,            // byte 7, 0x02 (BEP 4)
    Fast = 2,              // byte 7, 0x04 (BEP 4, BEP 6)
    NatTraversal = 3,      // byte 7, 0x08 (BEP 4)
    HybridV2 = 4,          // byte 7, 0x10 (BEP 4, BEP 52)
}

impl Extension {
    fn bit(self) -> u64 {
        1 << (self as u8)
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Extension::*;
        match self {
            AzureusMessaging => write!(f, "Azureus Messaging Protocol"),
            LocationAware => write!(f, "BitTorrent Location-aware Protocol"),
            Bep10 => write!(f, "BEP 10 Extension Protocol"),
            Dht => write!(f, "BitTorrent DHT"),
            XbtPex => write!(f, "XBT Peer Exchange"),
            Fast => write!(f, "Fast Extension"),
            NatTraversal => write!(f, "NAT Traversal"),
            HybridV2 => write!(f, "hybrid torrent legacy to v2 upgrade"),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
struct ExtensionSet(u64);

impl ExtensionSet {
    fn has(&self, ext: Extension) -> bool {
        self.0 & ext.bit() != 0
    }
}

impl fmt::Display for ExtensionSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut extset = self.0;
        let mut first = true;
        for ext in Extension::iter() {
            if extset & ext.bit() != 0 {
                if !std::mem::replace(&mut first, false) {
                    write!(f, ", ")?;
                }
                write!(f, "{ext}")?;
            }
            extset &= !ext.bit();
        }
        if extset != 0 {
            if !std::mem::replace(&mut first, false) {
                write!(f, ", ")?;
            }
            write!(f, "Unknown({extset:#018x})")?;
        }
        if first {
            write!(f, "<none>")?;
        }
        Ok(())
    }
}

impl From<ExtensionSet> for u64 {
    fn from(extset: ExtensionSet) -> u64 {
        extset.0
    }
}

impl From<u64> for ExtensionSet {
    fn from(extset: u64) -> ExtensionSet {
        ExtensionSet(extset)
    }
}

impl FromIterator<Extension> for ExtensionSet {
    fn from_iter<I>(iter: I) -> ExtensionSet
    where
        I: IntoIterator<Item = Extension>,
    {
        let mut value = 0;
        for ext in iter {
            value |= ext.bit();
        }
        ExtensionSet(value)
    }
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

    #[test]
    fn test_extension_iter() {
        use Extension::*;
        let mut iter = Extension::iter();
        assert_eq!(iter.next(), Some(AzureusMessaging));
        assert_eq!(iter.next(), Some(LocationAware));
        assert_eq!(iter.next(), Some(Bep10));
        assert_eq!(iter.next(), Some(Dht));
        assert_eq!(iter.next(), Some(XbtPex));
        assert_eq!(iter.next(), Some(Fast));
        assert_eq!(iter.next(), Some(NatTraversal));
        assert_eq!(iter.next(), Some(HybridV2));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_extension_set() {
        let extset = [Extension::Bep10, Extension::Dht, Extension::Fast]
            .into_iter()
            .collect::<ExtensionSet>();
        assert!(extset.has(Extension::Bep10));
        assert!(extset.has(Extension::Dht));
        assert!(extset.has(Extension::Fast));
        assert!(!extset.has(Extension::LocationAware));
        assert!(!extset.has(Extension::XbtPex));
        assert_eq!(
            extset.to_string(),
            "BEP 10 Extension Protocol, BitTorrent DHT, Fast Extension"
        );
        assert_eq!(u64::from(extset), 0x100005);
        assert_eq!(ExtensionSet::from(0x100005u64), extset);
    }

    #[test]
    fn test_default_extension_set() {
        let extset = ExtensionSet::default();
        assert_eq!(u64::from(extset), 0);
        assert_eq!(ExtensionSet::from(0), extset);
        for ext in Extension::iter() {
            assert!(!extset.has(ext));
        }
        assert_eq!(extset.to_string(), "<none>");
    }

    #[test]
    fn test_extension_set_unknown() {
        let extset = ExtensionSet::from(0x8404u64);
        for ext in Extension::iter() {
            if ext == Extension::Fast {
                assert!(extset.has(ext));
            } else {
                assert!(!extset.has(ext));
            }
        }
        assert_eq!(
            extset.to_string(),
            "Fast Extension, Unknown(0x0000000000008400)"
        );
    }

    #[test]
    fn test_extension_set_all_unknown() {
        let extset = ExtensionSet::from(0x8400u64);
        for ext in Extension::iter() {
            assert!(!extset.has(ext));
        }
        assert_eq!(extset.to_string(), "Unknown(0x0000000000008400)");
    }
}
