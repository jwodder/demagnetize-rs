#![expect(dead_code)]
mod actor;
mod messages;
mod table;
use bendy::decoding::{Error as BendyError, FromBencode, Object};
use bendy::encoding::{SingleItemEncoder, ToBencode};
use thiserror::Error;

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

impl FromBencode for NodeId {
    const EXPECTED_RECURSION_DEPTH: usize = 0;

    fn decode_bencode_object(object: Object<'_, '_>) -> Result<NodeId, BendyError> {
        let bs = object.try_into_bytes()?;
        let Ok(bytes) = bs.try_into() else {
            return Err(BendyError::malformed_content(NodeIdFromBytesError(
                bs.len(),
            )));
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

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("node ID is {0} bytes long, expected 20")]
struct NodeIdFromBytesError(usize);
