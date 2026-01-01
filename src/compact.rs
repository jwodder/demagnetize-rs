use bendy::decoding::{Error as BendyError, FromBencode, Object};
use bendy::encoding::{SingleItemEncoder, ToBencode};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use thiserror::Error;

pub(crate) trait ToCompact {
    fn to_compact(&self) -> Bytes;
}

pub(crate) trait FromCompact: Sized {
    type Error: std::error::Error + Send + Sync + 'static;

    fn from_compact(bs: &[u8]) -> Result<Self, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AsCompact<T>(pub(crate) T);

impl<T: ToCompact> ToBencode for AsCompact<T> {
    const MAX_DEPTH: usize = 0;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        let bs = self.0.to_compact();
        encoder.emit_bytes(&bs)
    }
}

impl<T: FromCompact> FromBencode for AsCompact<T> {
    const EXPECTED_RECURSION_DEPTH: usize = 0;

    fn decode_bencode_object(object: Object<'_, '_>) -> Result<AsCompact<T>, BendyError> {
        let bs = object.try_into_bytes()?;
        match T::from_compact(bs) {
            Ok(val) => Ok(AsCompact(val)),
            Err(e) => Err(BendyError::malformed_content(e)),
        }
    }
}

impl ToCompact for IpAddr {
    fn to_compact(&self) -> Bytes {
        let mut buf = BytesMut::new();
        match *self {
            IpAddr::V4(ip) => buf.put_slice(&ip.octets()),
            IpAddr::V6(ip) => buf.put_slice(&ip.octets()),
        }
        buf.freeze()
    }
}

impl ToCompact for SocketAddr {
    fn to_compact(&self) -> Bytes {
        let mut buf = BytesMut::new();
        match self.ip() {
            IpAddr::V4(ip) => buf.put_slice(&ip.octets()),
            IpAddr::V6(ip) => buf.put_slice(&ip.octets()),
        }
        buf.put_u16(self.port());
        buf.freeze()
    }
}

impl FromCompact for SocketAddr {
    type Error = FromCompactError;

    fn from_compact(bs: &[u8]) -> Result<SocketAddr, FromCompactError> {
        let mut buf = Bytes::from(bs.to_vec());
        match bs.len() {
            6 => {
                let ip = Ipv4Addr::from(buf.get_u32());
                let port = buf.get_u16();
                Ok(SocketAddrV4::new(ip, port).into())
            }
            18 => {
                let ip = Ipv6Addr::from(buf.get_u128());
                let port = buf.get_u16();
                Ok(SocketAddrV6::new(ip, port, 0, 0).into())
            }
            other => Err(FromCompactError {
                ty: "SocketAddr",
                length: other,
            }),
        }
    }
}

impl FromCompact for SocketAddrV4 {
    type Error = FromCompactError;

    fn from_compact(bs: &[u8]) -> Result<SocketAddrV4, FromCompactError> {
        let mut buf = Bytes::from(bs.to_vec());
        match bs.len() {
            6 => {
                // TODO: Use TryBytes?
                let ip = Ipv4Addr::from(buf.get_u32());
                let port = buf.get_u16();
                Ok(SocketAddrV4::new(ip, port))
            }
            other => Err(FromCompactError {
                ty: "SocketAddrV4",
                length: other,
            }),
        }
    }
}

impl FromCompact for SocketAddrV6 {
    type Error = FromCompactError;

    fn from_compact(bs: &[u8]) -> Result<SocketAddrV6, FromCompactError> {
        let mut buf = Bytes::from(bs.to_vec());
        match bs.len() {
            18 => {
                // TODO: Use TryBytes?
                let ip = Ipv6Addr::from(buf.get_u128());
                let port = buf.get_u16();
                Ok(SocketAddrV6::new(ip, port, 0, 0))
            }
            other => Err(FromCompactError {
                ty: "SocketAddrV6",
                length: other,
            }),
        }
    }
}

macro_rules! impl_vec_fromcompact {
    ($t:ty, $len:literal) => {
        impl FromCompact for Vec<$t> {
            type Error = crate::compact::FromCompactError;

            fn from_compact(mut bs: &[u8]) -> Result<Vec<$t>, crate::compact::FromCompactError> {
                let mut items = Vec::new();
                while !bs.is_empty() {
                    if bs.len() >= $len {
                        items.push(<$t>::from_compact(&bs[..$len])?);
                        bs = &bs[$len..];
                    } else {
                        // This will error with the correct `ty` field:
                        items.push(<$t>::from_compact(bs)?);
                        break;
                    }
                }
                Ok(items)
            }
        }
    };
}

impl_vec_fromcompact!(SocketAddrV4, 6);
impl_vec_fromcompact!(SocketAddrV6, 18);

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("compact representation of {ty} had invalid length {length}")]
pub(crate) struct FromCompactError {
    pub(crate) ty: &'static str,
    pub(crate) length: usize,
}
