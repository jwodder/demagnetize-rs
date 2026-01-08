#![expect(dead_code)]
mod actor;
mod messages;
pub(crate) use self::actor::{
    CreateDhtActorError, DhtActor, DhtHandle, DhtHandleError, FoundPeers,
};
use crate::compact::{FromCompact, FromCompactError};
use crate::types::InfoHash;
use crate::util::{PacketError, TryBytes, TryFromBuf};
use bendy::decoding::{Error as BendyError, FromBencode, Object};
use bendy::encoding::{SingleItemEncoder, ToBencode};
use bytes::{Buf, Bytes};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use tokio::net::lookup_host;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NodeId([u8; 20]);

impl NodeId {
    fn get_bit(&self, i: usize) -> bool {
        assert!(
            i < 160,
            "NodeId::get_bit() called with out-of-range value {i}"
        );
        let byteno = i / 8;
        let bitno = 7 - (i % 8);
        self.0[byteno] & (1 << bitno) != 0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl From<&[u8; 20]> for NodeId {
    fn from(value: &[u8; 20]) -> NodeId {
        NodeId(*value)
    }
}

impl std::ops::BitXor<InfoHash> for NodeId {
    type Output = Distance;

    fn bitxor(self, info_hash: InfoHash) -> Distance {
        let nid = self.0;
        let ih = info_hash.as_bytes();
        Distance(std::array::from_fn(|i| nid[i] & ih[i]))
    }
}

impl TryFromBuf for NodeId {
    fn try_from_buf(buf: &mut Bytes) -> Result<NodeId, PacketError> {
        if buf.len() >= 20 {
            let mut data = [0u8; 20];
            buf.copy_to_slice(&mut data);
            Ok(NodeId(data))
        } else {
            Err(PacketError::Short)
        }
    }
}

impl FromBencode for NodeId {
    const EXPECTED_RECURSION_DEPTH: usize = 0;

    fn decode_bencode_object(object: Object<'_, '_>) -> Result<NodeId, BendyError> {
        let bs = object.try_into_bytes()?;
        let Ok(bytes) = bs.try_into() else {
            return Err(BendyError::malformed_content(FromCompactError {
                ty: "NodeId",
                length: bs.len(),
            }));
        };
        Ok(NodeId(bytes))
    }
}

impl ToBencode for NodeId {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        encoder.emit_bytes(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Distance([u8; 20]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Node<T = IpAddr> {
    id: NodeId,
    ip: T,
    port: u16,
}

impl<T: Into<IpAddr> + Copy> Node<T> {
    fn address(&self) -> SocketAddr {
        SocketAddr::from((self.ip, self.port))
    }
}

impl<T: Into<IpAddr> + Copy> fmt::Display for Node<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DHT node {} at {}", self.id, self.address())
    }
}

impl From<Node<Ipv4Addr>> for Node<IpAddr> {
    fn from(value: Node<Ipv4Addr>) -> Node<IpAddr> {
        Node {
            id: value.id,
            ip: value.ip.into(),
            port: value.port,
        }
    }
}

impl From<Node<Ipv6Addr>> for Node<IpAddr> {
    fn from(value: Node<Ipv6Addr>) -> Node<IpAddr> {
        Node {
            id: value.id,
            ip: value.ip.into(),
            port: value.port,
        }
    }
}

impl FromCompact for Node<Ipv4Addr> {
    type Error = FromCompactError;

    fn from_compact(bs: &[u8]) -> Result<Node<Ipv4Addr>, FromCompactError> {
        let e = FromCompactError {
            ty: "NodeInfo<Ipv4Addr>",
            length: bs.len(),
        };
        let mut buf = TryBytes::from(bs);
        let id = buf.try_get::<NodeId>().map_err(|_| e)?;
        let ip = buf.try_get::<Ipv4Addr>().map_err(|_| e)?;
        let port = buf.try_get::<u16>().map_err(|_| e)?;
        buf.eof().map_err(|_| e)?;
        Ok(Node { id, ip, port })
    }
}

impl FromCompact for Node<Ipv6Addr> {
    type Error = FromCompactError;

    fn from_compact(bs: &[u8]) -> Result<Node<Ipv6Addr>, FromCompactError> {
        let e = FromCompactError {
            ty: "NodeInfo<Ipv6Addr>",
            length: bs.len(),
        };
        let mut buf = TryBytes::from(bs);
        let id = buf.try_get::<NodeId>().map_err(|_| e)?;
        let ip = buf.try_get::<Ipv6Addr>().map_err(|_| e)?;
        let port = buf.try_get::<u16>().map_err(|_| e)?;
        buf.eof().map_err(|_| e)?;
        Ok(Node { id, ip, port })
    }
}

impl_vec_fromcompact!(Node<Ipv4Addr>, 26);
impl_vec_fromcompact!(Node<Ipv6Addr>, 38);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InetAddr {
    host: url::Host,
    port: u16,
}

impl InetAddr {
    // This needs to consume self so that the resulting future will be 'static,
    // thereby allowing DhtActor::run() to be passed to tokio::spawn().
    async fn resolve(self, use_ipv6: bool) -> Option<SocketAddr> {
        match self.host {
            url::Host::Domain(ref domain) => {
                match lookup_host((domain.as_str(), self.port)).await {
                    Ok(mut iter) => {
                        if let Some(addr) = iter.find(|a| use_ipv6 || a.is_ipv4()) {
                            log::debug!("Resolved domain {domain:?} to {}", addr.ip());
                            Some(addr)
                        } else {
                            log::warn!("Failed to resolve domain {domain:?} to any IP addresses");
                            None
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to resolve domain {domain:?}: {e}");
                        None
                    }
                }
            }
            url::Host::Ipv4(ip) => Some(SocketAddr::from((ip, self.port))),
            url::Host::Ipv6(ip) => use_ipv6.then(|| SocketAddr::from((ip, self.port))),
        }
    }
}

impl std::str::FromStr for InetAddr {
    type Err = ParseInetAddrError;

    fn from_str(s: &str) -> Result<InetAddr, ParseInetAddrError> {
        let (host, port) = s.rsplit_once(':').ok_or(ParseInetAddrError)?;
        let port = port.parse::<u16>().map_err(|_| ParseInetAddrError)?;
        // Note that url::Host::parse() requires IPv6 addresses to be input
        // with surrounding brackets, so don't remove them.
        let host = url::Host::parse(host).map_err(|_| ParseInetAddrError)?;
        Ok(InetAddr { host, port })
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("invalid <host>:<port> string")]
pub(crate) struct ParseInetAddrError;

impl<'de> Deserialize<'de> for InetAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = InetAddr;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a <host>:<port> string")
            }

            fn visit_str<E>(self, input: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                input
                    .parse::<InetAddr>()
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(input), &self))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod inet_addr {
        use super::*;
        use assert_matches::assert_matches;
        use rstest::rstest;

        #[rstest]
        #[case("www.example.com:80", "www.example.com", 80)]
        fn parse_domain_host(#[case] s: &str, #[case] host: &str, #[case] port: u16) {
            let addr = s.parse::<InetAddr>().unwrap();
            assert_matches!(addr.host, url::Host::Domain(domain) => {
                assert_eq!(domain, host);
            });
            assert_eq!(addr.port, port);
        }

        #[rstest]
        #[case("127.0.0.1:80", "127.0.0.1", 80)]
        #[case("80:61", "0.0.0.80", 61)]
        fn parse_ipv4_host(#[case] s: &str, #[case] host: Ipv4Addr, #[case] port: u16) {
            let addr = s.parse::<InetAddr>().unwrap();
            assert_matches!(addr.host, url::Host::Ipv4(ip) => {
                assert_eq!(ip, host);
            });
            assert_eq!(addr.port, port);
        }

        #[rstest]
        #[case("[::1]:80", "::1", 80)]
        #[case("[::ffff:127.0.0.1]:80", "::ffff:127.0.0.1", 80)]
        #[case("[2001:abcd::1234]:80", "2001:abcd::1234", 80)]
        fn parse_ipv6_host(#[case] s: &str, #[case] host: Ipv6Addr, #[case] port: u16) {
            let addr = s.parse::<InetAddr>().unwrap();
            assert_matches!(addr.host, url::Host::Ipv6(ip) => {
                assert_eq!(ip, host);
            });
            assert_eq!(addr.port, port);
        }

        #[rstest]
        #[case("www.example.com")]
        #[case("www.example.com:80:61")]
        #[case("[www.example.com]:60069")]
        #[case("[127.0.0.1]:60069")]
        #[case("127.0.0.1")]
        #[case("::1:8000")]
        #[case("::ffff:127.0.0.1:8000")]
        #[case("2001:abcd::1234:80")]
        fn bad_parse(#[case] s: &str) {
            let r = s.parse::<InetAddr>();
            assert!(r.is_err());
        }
    }
}
