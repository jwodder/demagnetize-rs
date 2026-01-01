#![expect(dead_code)]
mod actor;
mod messages;
mod table;
use crate::compact::{FromCompact, FromCompactError};
use crate::util::{PacketError, TryBytes, TryFromBuf};
use bendy::decoding::{Error as BendyError, FromBencode, Object};
use bendy::encoding::{SingleItemEncoder, ToBencode};
use bytes::{Buf, Bytes};
use std::net::{Ipv4Addr, Ipv6Addr};

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

impl From<&[u8; 20]> for NodeId {
    fn from(value: &[u8; 20]) -> NodeId {
        NodeId(*value)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeInfo<T> {
    id: NodeId,
    ip: T,
    port: u16,
}

impl FromCompact for NodeInfo<Ipv4Addr> {
    type Error = FromCompactError;

    fn from_compact(bs: &[u8]) -> Result<NodeInfo<Ipv4Addr>, FromCompactError> {
        let e = FromCompactError {
            ty: "NodeInfo<Ipv4Addr>",
            length: bs.len(),
        };
        let mut buf = TryBytes::from(bs);
        let id = buf.try_get::<NodeId>().map_err(|_| e)?;
        let ip = buf.try_get::<Ipv4Addr>().map_err(|_| e)?;
        let port = buf.try_get::<u16>().map_err(|_| e)?;
        buf.eof().map_err(|_| e)?;
        Ok(NodeInfo { id, ip, port })
    }
}

impl FromCompact for NodeInfo<Ipv6Addr> {
    type Error = FromCompactError;

    fn from_compact(bs: &[u8]) -> Result<NodeInfo<Ipv6Addr>, FromCompactError> {
        let e = FromCompactError {
            ty: "NodeInfo<Ipv6Addr>",
            length: bs.len(),
        };
        let mut buf = TryBytes::from(bs);
        let id = buf.try_get::<NodeId>().map_err(|_| e)?;
        let ip = buf.try_get::<Ipv6Addr>().map_err(|_| e)?;
        let port = buf.try_get::<u16>().map_err(|_| e)?;
        buf.eof().map_err(|_| e)?;
        Ok(NodeInfo { id, ip, port })
    }
}

impl_vec_fromcompact!(NodeInfo<Ipv4Addr>, 26);
impl_vec_fromcompact!(NodeInfo<Ipv6Addr>, 38);
