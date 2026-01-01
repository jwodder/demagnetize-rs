#![expect(unused_variables)]
use super::NodeId;
use crate::peer::Peer;
use crate::types::InfoHash;
use bendy::decoding::{Error as BendyError, FromBencode, Object};
use bendy::encoding::{AsString, SingleItemEncoder, ToBencode};
use bytes::{BufMut, Bytes, BytesMut};
use std::net::{IpAddr, SocketAddr};

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
        encoder.emit_dict(|mut e| {
            e.emit_pair_with(b"a", |enc2| {
                enc2.emit_dict(|mut a| {
                    a.emit_pair(b"id", self.id)?;
                    Ok(())
                })
            })?;
            e.emit_pair(b"q", AsString(b"ping"))?;
            e.emit_pair(b"t", AsString(&self.t))?;
            if let Some(ro) = self.ro {
                e.emit_pair(b"ro", u8::from(ro))?;
            }
            if let Some(ref v) = self.v {
                e.emit_pair(b"v", v)?;
            }
            e.emit_pair(b"y", AsString(b"q"))?;
            Ok(())
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PingResponse {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) id: NodeId,
    pub(super) ip: Option<SocketAddr>,
}

impl FromBencode for PingResponse {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<PingResponse, BendyError> {
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
        encoder.emit_dict(|mut e| {
            e.emit_pair_with(b"a", |enc2| {
                enc2.emit_dict(|mut a| {
                    a.emit_pair(b"id", self.id)?;
                    a.emit_pair(b"target", self.target)?;
                    if let Some(ref want) = self.want {
                        a.emit_pair_with(b"want", |enc3| {
                            enc3.emit_list(|wlst| {
                                for &w in want {
                                    wlst.emit_str(w.as_str())?;
                                }
                                Ok(())
                            })
                        })?;
                    }
                    Ok(())
                })
            })?;
            e.emit_pair(b"q", AsString(b"find_node"))?;
            e.emit_pair(b"t", AsString(&self.t))?;
            if let Some(ro) = self.ro {
                e.emit_pair(b"ro", u8::from(ro))?;
            }
            if let Some(ref v) = self.v {
                e.emit_pair(b"v", v)?;
            }
            e.emit_pair(b"y", AsString(b"q"))?;
            Ok(())
        })
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

impl FromBencode for FindNodeResponse {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<FindNodeResponse, BendyError> {
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
        encoder.emit_dict(|mut e| {
            e.emit_pair_with(b"a", |enc2| {
                enc2.emit_dict(|mut a| {
                    a.emit_pair(b"id", self.id)?;
                    a.emit_pair(b"info_hash", AsString(self.info_hash.as_bytes()))?;
                    if let Some(ref want) = self.want {
                        a.emit_pair_with(b"want", |enc3| {
                            enc3.emit_list(|wlst| {
                                for &w in want {
                                    wlst.emit_str(w.as_str())?;
                                }
                                Ok(())
                            })
                        })?;
                    }
                    Ok(())
                })
            })?;
            e.emit_pair(b"q", AsString(b"get_peers"))?;
            e.emit_pair(b"t", AsString(&self.t))?;
            if let Some(ro) = self.ro {
                e.emit_pair(b"ro", u8::from(ro))?;
            }
            if let Some(ref v) = self.v {
                e.emit_pair(b"v", v)?;
            }
            e.emit_pair(b"y", AsString(b"q"))?;
            Ok(())
        })
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

impl FromBencode for GetPeersResponse {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<GetPeersResponse, BendyError> {
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
        encoder.emit_dict(|mut e| {
            e.emit_pair_with(b"a", |enc2| {
                enc2.emit_dict(|mut a| {
                    a.emit_pair(b"id", self.id)?;
                    if let Some(flag) = self.implied_port {
                        a.emit_pair(b"implied_port", u8::from(flag))?;
                    }
                    a.emit_pair(b"info_hash", AsString(self.info_hash.as_bytes()))?;
                    a.emit_pair(b"port", self.port)?;
                    a.emit_pair(b"token", AsString(&self.token))?;
                    Ok(())
                })
            })?;
            e.emit_pair(b"q", AsString(b"announce_peer"))?;
            e.emit_pair(b"t", AsString(&self.t))?;
            if let Some(ro) = self.ro {
                e.emit_pair(b"ro", u8::from(ro))?;
            }
            if let Some(ref v) = self.v {
                e.emit_pair(b"v", v)?;
            }
            e.emit_pair(b"y", AsString(b"q"))?;
            Ok(())
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AnnouncePeerResponse {
    pub(super) t: Bytes,
    pub(super) v: Option<String>,
    pub(super) id: NodeId,
    pub(super) ip: Option<SocketAddr>,
}

impl FromBencode for AnnouncePeerResponse {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<AnnouncePeerResponse, BendyError> {
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

impl FromBencode for RpcError {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<RpcError, BendyError> {
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

impl Want {
    fn as_str(self) -> &'static str {
        match self {
            Want::N4 => "n4",
            Want::N6 => "n6",
        }
    }
}

fn socket_addr2bencode(addr: SocketAddr) -> AsString<Bytes> {
    let mut buf = BytesMut::new();
    match addr.ip() {
        IpAddr::V4(ip) => buf.put_slice(&ip.octets()),
        IpAddr::V6(ip) => buf.put_slice(&ip.octets()),
    }
    buf.put_u16(addr.port());
    AsString(buf.freeze())
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
            let msg =
                decode_bencode::<RpcError>(b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee")
                    .unwrap();
            assert_eq!(
                msg,
                RpcError {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    error_code: 201,
                    error_message: "A Generic Error Ocurred".into(),
                }
            );
        }

        #[test]
        fn ping_response() {
            let msg =
                decode_bencode::<PingResponse>(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re")
                    .unwrap();
            assert_eq!(
                msg,
                PingResponse {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"mnopqrstuvwxyz123456"),
                    ip: None,
                }
            );
        }

        #[test]
        fn find_node_response() {
            let msg = decode_bencode::<FindNodeResponse>(
                b"d1:rd2:id20:0123456789abcdefghij5:nodes26:mnopqrstuvwxyz123456iiiippe1:t2:aa1:y1:re",
            )
            .unwrap();
            assert_eq!(
                msg,
                FindNodeResponse {
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
                }
            );
        }

        #[test]
        fn get_peers_response_values() {
            let msg = decode_bencode::<GetPeersResponse>(b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re").unwrap();
            assert_eq!(
                msg,
                GetPeersResponse {
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
                }
            );
        }

        #[test]
        fn get_peers_response_nodes() {
            let msg = decode_bencode::<GetPeersResponse>(b"d1:rd2:id20:abcdefghij01234567895:nodes26:mnopqrstuvwxyz123456iiiipp5:token8:aoeusnthe1:t2:aa1:y1:re").unwrap();
            assert_eq!(
                msg,
                GetPeersResponse {
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
                }
            );
        }

        #[test]
        fn announce_peer_response() {
            let msg = decode_bencode::<AnnouncePeerResponse>(
                b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re",
            )
            .unwrap();
            assert_eq!(
                msg,
                AnnouncePeerResponse {
                    t: Bytes::from(b"aa".as_slice()),
                    v: None,
                    id: NodeId(*b"mnopqrstuvwxyz123456"),
                    ip: None,
                }
            );
        }
    }

    mod encode {
        use super::*;

        #[test]
        fn ping_query() {
            let msg = PingQuery {
                t: Bytes::from(b"aa".as_slice()),
                v: None,
                id: NodeId(*b"abcdefghij0123456789"),
                ro: None,
            };
            assert_eq!(
                msg.to_bencode().unwrap(),
                b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
            );
        }

        #[test]
        fn find_node_query() {
            let msg = FindNodeQuery {
                t: Bytes::from(b"aa".as_slice()),
                v: None,
                id: NodeId(*b"abcdefghij0123456789"),
                target: NodeId(*b"mnopqrstuvwxyz123456"),
                ro: None,
                want: None,
            };
            assert_eq!(msg.to_bencode().unwrap(), b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe");
        }

        #[test]
        fn get_peers_query() {
            let msg = GetPeersQuery {
                t: Bytes::from(b"aa".as_slice()),
                v: None,
                id: NodeId(*b"abcdefghij0123456789"),
                info_hash: b"mnopqrstuvwxyz123456".to_vec().try_into().unwrap(),
                ro: None,
                want: None,
            };
            assert_eq!(msg.to_bencode().unwrap(), b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");
        }

        #[test]
        fn announce_peer_query() {
            let msg = AnnouncePeerQuery {
                t: Bytes::from(b"aa".as_slice()),
                v: None,
                id: NodeId(*b"abcdefghij0123456789"),
                info_hash: b"mnopqrstuvwxyz123456".to_vec().try_into().unwrap(),
                port: 6881,
                token: Bytes::from(b"aoeusnth".as_slice()),
                implied_port: Some(true),
                ro: None,
            };
            assert_eq!(msg.to_bencode().unwrap(), b"d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe");
        }
    }
}

// TO TEST:
// - Decoding:
//  - "values" has IPv6 peers
//  - "nodes6"
//  - "ip" = IPv4
//  - "ip" = IPv6
// - Encoding:
//  - "want"
