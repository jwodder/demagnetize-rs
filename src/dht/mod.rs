#![expect(dead_code)]
mod actor;
mod messages;
use crate::compact::{FromCompact, FromCompactError};
use crate::types::InfoHash;
use crate::util::{PacketError, TryBytes, TryFromBuf};
use bendy::decoding::{Error as BendyError, FromBencode, Object};
use bendy::encoding::{SingleItemEncoder, ToBencode};
use bytes::{Buf, Bytes};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    async fn resolve(&self, use_ipv6: bool) -> Option<SocketAddr> {
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
