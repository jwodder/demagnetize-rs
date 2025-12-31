#![expect(unused_variables)]
use super::NodeId;
use crate::peer::Peer;
use crate::types::InfoHash;
use bendy::decoding::{Error as BendyError, FromBencode, Object};
use bendy::encoding::{SingleItemEncoder, ToBencode};
use bytes::Bytes;
use std::net::{IpAddr, SocketAddr};

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
    pub(super) ip: Option<SocketAddr>,
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
    pub(super) ip: Option<SocketAddr>,
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
    pub(super) ip: Option<SocketAddr>,
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
    pub(super) ip: Option<SocketAddr>,
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

#[cfg(test)]
mod tests {
    use super::*;

    mod decode {
        use super::*;
        use crate::util::decode_bencode;
        use std::net::Ipv4Addr;

        #[test]
        fn error() {
            let msg = decode_bencode::<DhtMessage>(
                b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee",
            )
            .unwrap();
            assert_eq!(
                msg,
                DhtMessage::Error(RpcError {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    error_code: 201,
                    error_message: "A Generic Error Ocurred".into(),
                })
            );
        }

        #[test]
        fn ping_query() {
            let msg = decode_bencode::<DhtMessage>(
                b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
            )
            .unwrap();
            assert_eq!(
                msg,
                DhtMessage::PingQuery(PingQuery {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"abcdefghij0123456789"),
                    ro: None,
                })
            );
        }

        #[test]
        fn ping_response() {
            let msg =
                decode_bencode::<DhtMessage>(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re")
                    .unwrap();
            assert_eq!(
                msg,
                DhtMessage::PingResponse(PingResponse {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"mnopqrstuvwxyz123456"),
                    ip: None,
                })
            );
        }

        #[test]
        fn find_node_query() {
            let msg = decode_bencode::<DhtMessage>(
                b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe",
            )
            .unwrap();
            assert_eq!(
                msg,
                DhtMessage::FindNodeQuery(FindNodeQuery {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"abcdefghij0123456789"),
                    target: NodeId(*b"mnopqrstuvwxyz123456"),
                    ro: None,
                    want: None,
                })
            );
        }

        #[test]
        fn find_node_response() {
            let msg = decode_bencode::<DhtMessage>(
                b"d1:rd2:id20:0123456789abcdefghij5:nodes26:mnopqrstuvwxyz123456iiiippe1:t2:aa1:y1:re",
            )
            .unwrap();
            assert_eq!(
                msg,
                DhtMessage::FindNodeResponse(FindNodeResponse {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"0123456789abcdefghij"),
                    nodes: vec![NodeInfo {
                        id: NodeId(*b"mnopqrstuvwxyz123456"),
                        ip: IpAddr::V4(Ipv4Addr::new(105, 105, 105, 105)),
                        port: 28784,
                    }],
                    nodes6: Vec::new(),
                    ip: None,
                })
            );
        }

        #[test]
        fn get_peers_query() {
            let msg = decode_bencode::<DhtMessage>(b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe").unwrap();
            assert_eq!(
                msg,
                DhtMessage::GetPeersQuery(GetPeersQuery {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"abcdefghij0123456789"),
                    info_hash: b"mnopqrstuvwxyz123456".to_vec().try_into().unwrap(),
                    ro: None,
                    want: None,
                })
            );
        }

        #[test]
        fn get_peers_response_values() {
            let msg = decode_bencode::<DhtMessage>(b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re").unwrap();
            assert_eq!(
                msg,
                DhtMessage::GetPeersResponse(GetPeersResponse {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"abcdefghij0123456789"),
                    values: vec![
                        "141.170.152.145:11893".parse().unwrap(),
                        "151.144.150.164:28269".parse().unwrap(),
                    ],
                    nodes: Vec::new(),
                    nodes6: Vec::new(),
                    token: Bytes::from(b"aoeusnth".as_slice()),
                    ip: None,
                })
            );
        }

        #[test]
        fn get_peers_response_nodes() {
            let msg = decode_bencode::<DhtMessage>(b"d1:rd2:id20:abcdefghij01234567895:nodes26:mnopqrstuvwxyz123456iiiipp5:token8:aoeusnthe1:t2:aa1:y1:re").unwrap();
            assert_eq!(
                msg,
                DhtMessage::GetPeersResponse(GetPeersResponse {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"abcdefghij0123456789"),
                    values: Vec::new(),
                    nodes: vec![NodeInfo {
                        id: NodeId(*b"mnopqrstuvwxyz123456"),
                        ip: IpAddr::V4(Ipv4Addr::new(105, 105, 105, 105)),
                        port: 28784,
                    }],
                    nodes6: Vec::new(),
                    token: Bytes::from(b"aoeusnth".as_slice()),
                    ip: None,
                })
            );
        }

        #[test]
        fn announce_peer_query() {
            let msg = decode_bencode::<DhtMessage>(b"d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe").unwrap();
            assert_eq!(
                msg,
                DhtMessage::AnnouncePeerQuery(AnnouncePeerQuery {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"abcdefghij0123456789"),
                    info_hash: b"mnopqrstuvwxyz123456".to_vec().try_into().unwrap(),
                    port: 6881,
                    token: Bytes::from(b"aoeusnth".as_slice()),
                    implied_port: Some(true),
                    ro: None
                })
            );
        }

        #[test]
        fn announce_peer_response() {
            let msg =
                decode_bencode::<DhtMessage>(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re")
                    .unwrap();
            assert_eq!(
                msg,
                DhtMessage::AnnouncePeerResponse(AnnouncePeerResponse {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"mnopqrstuvwxyz123456"),
                    ip: None,
                })
            );
        }
    }
}
