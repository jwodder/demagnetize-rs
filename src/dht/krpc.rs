#![expect(unused_variables)]
use super::NodeId;
use crate::peer::Peer;
use crate::types::InfoHash;
use bendy::decoding::{Error as BendyError, FromBencode, Object};
use bendy::encoding::{SingleItemEncoder, ToBencode};
use bytes::Bytes;
use std::net::IpAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DhtMessage {
    PingQuery(PingQuery),
    PingResponse(PingResponse),
    FindNodeQuery(FindNodeQuery),
    FindNodeResponse(FindNodeResponse),
    GetPeersQuery(GetPeersQuery),
    GetPeersResponse(GetPeersResponse),
    AnnouncePeerQuery(AnnouncePeerQuery),
    AnnouncePeerResponse(AnnouncePeerResponse),
    Error(RpcError),
}

impl FromBencode for DhtMessage {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<DhtMessage, BendyError> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PingQuery {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) id: NodeId,
    pub(super) ro: Option<bool>,
}

impl ToBencode for PingQuery {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PingResponse {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) id: NodeId,
}

impl ToBencode for PingResponse {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FindNodeQuery {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) id: NodeId,
    pub(super) target: NodeId,
    pub(super) ro: Option<bool>,
    pub(super) want: Option<Vec<Want>>,
}

impl ToBencode for FindNodeQuery {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FindNodeResponse {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) id: NodeId,
    pub(super) nodes: Vec<NodeInfo>,
    pub(super) nodes6: Vec<NodeInfo>,
}

impl ToBencode for FindNodeResponse {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GetPeersQuery {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) id: NodeId,
    pub(super) info_hash: InfoHash,
    pub(super) ro: Option<bool>,
    pub(super) want: Option<Vec<Want>>,
}

impl ToBencode for GetPeersQuery {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GetPeersResponse {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) id: NodeId,
    pub(super) values: Vec<Peer>,
    pub(super) nodes: Vec<NodeInfo>,
    pub(super) nodes6: Vec<NodeInfo>,
    pub(super) token: Bytes,
}

impl ToBencode for GetPeersResponse {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AnnouncePeerQuery {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) id: NodeId,
    pub(super) info_hash: InfoHash,
    pub(super) port: u16,
    pub(super) token: Bytes,
    pub(super) implied_port: Option<bool>,
    pub(super) ro: Option<bool>,
}

impl ToBencode for AnnouncePeerQuery {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AnnouncePeerResponse {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) id: NodeId,
}

impl ToBencode for AnnouncePeerResponse {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RpcError {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) error_code: u32,
    pub(super) error_message: String,
}

impl ToBencode for RpcError {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NodeInfo {
    pub(super) id: NodeId,
    pub(super) ip: IpAddr,
    pub(super) port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Want {
    N4,
    N6,
}
