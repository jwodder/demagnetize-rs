use super::NodeId;
use crate::compact::{AsCompact, FromCompact, FromCompactError};
use crate::peer::Peer;
use crate::types::InfoHash;
use crate::util::TryBytes;
use bendy::decoding::{Decoder, Error as BendyError, FromBencode, Object, ResultExt};
use bendy::encoding::{AsString, SingleItemEncoder, ToBencode};
use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PingQuery {
    pub(super) transaction_id: Bytes,
    pub(super) client: Option<String>,
    pub(super) node_id: NodeId,
    pub(super) read_only: Option<bool>,
}

impl ToBencode for PingQuery {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair_with(b"a", |enc2| {
                enc2.emit_dict(|mut a| {
                    a.emit_pair(b"id", self.node_id)?;
                    Ok(())
                })
            })?;
            e.emit_pair(b"q", AsString(b"ping"))?;
            e.emit_pair(b"t", AsString(&self.transaction_id))?;
            if let Some(ro) = self.read_only {
                e.emit_pair(b"ro", u8::from(ro))?;
            }
            if let Some(ref v) = self.client {
                e.emit_pair(b"v", v)?;
            }
            e.emit_pair(b"y", AsString(b"q"))?;
            Ok(())
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PingResponse {
    pub(super) transaction_id: Bytes,
    pub(super) client: Option<String>,
    pub(super) node_id: NodeId,
    pub(super) your_addr: Option<SocketAddr>,
}

impl FromBencode for PingResponse {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<PingResponse, BendyError> {
        let mut transaction_id = None;
        let mut client = None;
        let mut node_id = None;
        let mut your_addr = None;
        let mut dd = object.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            match kv {
                (b"t", val) => {
                    let data = AsString::<Vec<u8>>::decode_bencode_object(val).context("t")?;
                    transaction_id = Some(Bytes::from(data.0));
                }
                (b"v", val) => {
                    client = Some(
                        String::from_utf8_lossy(val.try_into_bytes().context("v")?).into_owned(),
                    );
                }
                (b"y", val) => {
                    let data = String::decode_bencode_object(val).context("y")?;
                    if data != "r" {
                        return Err(BendyError::malformed_content(InvalidYField {
                            expected: "r",
                            got: data,
                        })
                        .context("y"));
                    }
                }
                (b"r", val) => {
                    let mut rdict = val.try_into_dictionary().context("r")?;
                    while let Some(rkv) = rdict.next_pair().context("r")? {
                        if let (b"id", idval) = rkv {
                            node_id = Some(NodeId::decode_bencode_object(idval).context("r.id")?);
                        }
                    }
                }
                (b"ip", val) => {
                    let addr = AsCompact::<SocketAddr>::decode_bencode_object(val).context("ip")?;
                    your_addr = Some(addr.0);
                }
                _ => (),
            }
        }
        let transaction_id = transaction_id.ok_or_else(|| BendyError::missing_field("t"))?;
        let node_id = node_id.ok_or_else(|| BendyError::missing_field("r.id"))?;
        Ok(PingResponse {
            transaction_id,
            client,
            node_id,
            your_addr,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FindNodeQuery {
    pub(super) transaction_id: Bytes,
    pub(super) client: Option<String>,
    pub(super) node_id: NodeId,
    pub(super) target: NodeId,
    pub(super) read_only: Option<bool>,
    pub(super) want: Option<Vec<Want>>,
}

impl ToBencode for FindNodeQuery {
    const MAX_DEPTH: usize = 3;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair_with(b"a", |enc2| {
                enc2.emit_dict(|mut a| {
                    a.emit_pair(b"id", self.node_id)?;
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
            e.emit_pair(b"t", AsString(&self.transaction_id))?;
            if let Some(ro) = self.read_only {
                e.emit_pair(b"ro", u8::from(ro))?;
            }
            if let Some(ref v) = self.client {
                e.emit_pair(b"v", v)?;
            }
            e.emit_pair(b"y", AsString(b"q"))?;
            Ok(())
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FindNodeResponse {
    pub(super) transaction_id: Bytes,
    pub(super) client: Option<String>,
    pub(super) node_id: NodeId,
    pub(super) nodes: Vec<NodeInfo>,
    pub(super) nodes6: Vec<NodeInfo>,
    pub(super) your_addr: Option<SocketAddr>,
}

impl FromBencode for FindNodeResponse {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<FindNodeResponse, BendyError> {
        let mut transaction_id = None;
        let mut client = None;
        let mut node_id = None;
        let mut nodes = Vec::new();
        let mut nodes6 = Vec::new();
        let mut your_addr = None;
        let mut dd = object.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            match kv {
                (b"t", val) => {
                    let data = AsString::<Vec<u8>>::decode_bencode_object(val).context("t")?;
                    transaction_id = Some(Bytes::from(data.0));
                }
                (b"v", val) => {
                    client = Some(
                        String::from_utf8_lossy(val.try_into_bytes().context("v")?).into_owned(),
                    );
                }
                (b"y", val) => {
                    let data = String::decode_bencode_object(val).context("y")?;
                    if data != "r" {
                        return Err(BendyError::malformed_content(InvalidYField {
                            expected: "r",
                            got: data,
                        })
                        .context("y"));
                    }
                }
                (b"r", val) => {
                    let mut rdict = val.try_into_dictionary().context("r")?;
                    while let Some(rkv) = rdict.next_pair().context("r")? {
                        match rkv {
                            (b"id", rval) => {
                                node_id =
                                    Some(NodeId::decode_bencode_object(rval).context("r.id")?);
                            }
                            (b"nodes", rval) => {
                                let ns = AsCompact::<Vec<NodeInfoV4>>::decode_bencode_object(rval)
                                    .context("r.nodes")?;
                                nodes.extend(ns.0.into_iter().map(NodeInfo::from));
                            }
                            (b"nodes6", rval) => {
                                let ns = AsCompact::<Vec<NodeInfoV6>>::decode_bencode_object(rval)
                                    .context("r.nodes6")?;
                                nodes6.extend(ns.0.into_iter().map(NodeInfo::from));
                            }
                            _ => (),
                        }
                    }
                }
                (b"ip", val) => {
                    let addr = AsCompact::<SocketAddr>::decode_bencode_object(val).context("ip")?;
                    your_addr = Some(addr.0);
                }
                _ => (),
            }
        }
        let transaction_id = transaction_id.ok_or_else(|| BendyError::missing_field("t"))?;
        let node_id = node_id.ok_or_else(|| BendyError::missing_field("r.id"))?;
        Ok(FindNodeResponse {
            transaction_id,
            client,
            node_id,
            nodes,
            nodes6,
            your_addr,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GetPeersQuery {
    pub(super) transaction_id: Bytes,
    pub(super) client: Option<String>,
    pub(super) node_id: NodeId,
    pub(super) info_hash: InfoHash,
    pub(super) read_only: Option<bool>,
    pub(super) want: Option<Vec<Want>>,
}

impl ToBencode for GetPeersQuery {
    const MAX_DEPTH: usize = 3;

    fn encode(&self, encoder: SingleItemEncoder<'_>) -> Result<(), bendy::encoding::Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair_with(b"a", |enc2| {
                enc2.emit_dict(|mut a| {
                    a.emit_pair(b"id", self.node_id)?;
                    a.emit_pair(b"info_hash", self.info_hash)?;
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
            e.emit_pair(b"t", AsString(&self.transaction_id))?;
            if let Some(ro) = self.read_only {
                e.emit_pair(b"ro", u8::from(ro))?;
            }
            if let Some(ref v) = self.client {
                e.emit_pair(b"v", v)?;
            }
            e.emit_pair(b"y", AsString(b"q"))?;
            Ok(())
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GetPeersResponse {
    pub(super) transaction_id: Bytes,
    pub(super) client: Option<String>,
    pub(super) node_id: NodeId,
    pub(super) values: Vec<Peer>,
    pub(super) nodes: Vec<NodeInfo>,
    pub(super) nodes6: Vec<NodeInfo>,
    pub(super) token: Bytes,
    pub(super) your_addr: Option<SocketAddr>,
}

impl FromBencode for GetPeersResponse {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<GetPeersResponse, BendyError> {
        let mut transaction_id = None;
        let mut client = None;
        let mut node_id = None;
        let mut values = Vec::new();
        let mut nodes = Vec::new();
        let mut nodes6 = Vec::new();
        let mut token = None;
        let mut your_addr = None;
        let mut dd = object.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            match kv {
                (b"t", val) => {
                    let data = AsString::<Vec<u8>>::decode_bencode_object(val).context("t")?;
                    transaction_id = Some(Bytes::from(data.0));
                }
                (b"v", val) => {
                    client = Some(
                        String::from_utf8_lossy(val.try_into_bytes().context("v")?).into_owned(),
                    );
                }
                (b"y", val) => {
                    let data = String::decode_bencode_object(val).context("y")?;
                    if data != "r" {
                        return Err(BendyError::malformed_content(InvalidYField {
                            expected: "r",
                            got: data,
                        })
                        .context("y"));
                    }
                }
                (b"r", val) => {
                    let mut rdict = val.try_into_dictionary().context("r")?;
                    while let Some(rkv) = rdict.next_pair().context("r")? {
                        match rkv {
                            (b"id", rval) => {
                                node_id =
                                    Some(NodeId::decode_bencode_object(rval).context("r.id")?);
                            }
                            (b"nodes", rval) => {
                                let ns = AsCompact::<Vec<NodeInfoV4>>::decode_bencode_object(rval)
                                    .context("r.nodes")?;
                                nodes.extend(ns.0.into_iter().map(NodeInfo::from));
                            }
                            (b"nodes6", rval) => {
                                let ns = AsCompact::<Vec<NodeInfoV6>>::decode_bencode_object(rval)
                                    .context("r.nodes6")?;
                                nodes6.extend(ns.0.into_iter().map(NodeInfo::from));
                            }
                            (b"values", rval) => {
                                let mut vs = rval.try_into_list().context("r.values")?;
                                while let Some(item) = vs.next_object().context("r.values")? {
                                    let addr = AsCompact::<SocketAddr>::decode_bencode_object(item)
                                        .context("r.values")?;
                                    values.push(Peer::from(addr.0));
                                }
                            }
                            (b"token", rval) => {
                                let data = AsString::<Vec<u8>>::decode_bencode_object(rval)
                                    .context("r.token")?;
                                token = Some(Bytes::from(data.0));
                            }
                            _ => (),
                        }
                    }
                }
                (b"ip", val) => {
                    let addr = AsCompact::<SocketAddr>::decode_bencode_object(val).context("ip")?;
                    your_addr = Some(addr.0);
                }
                _ => (),
            }
        }
        let transaction_id = transaction_id.ok_or_else(|| BendyError::missing_field("t"))?;
        let node_id = node_id.ok_or_else(|| BendyError::missing_field("r.id"))?;
        let token = token.ok_or_else(|| BendyError::missing_field("r.token"))?;
        Ok(GetPeersResponse {
            transaction_id,
            client,
            node_id,
            values,
            nodes,
            nodes6,
            token,
            your_addr,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ErrorResponse {
    pub(super) transaction_id: Bytes,
    pub(super) client: Option<String>,
    pub(super) error_code: u32,
    pub(super) error_message: String,
}

impl FromBencode for ErrorResponse {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<ErrorResponse, BendyError> {
        let mut transaction_id = None;
        let mut client = None;
        let mut error_code = None;
        let mut error_message = None;
        let mut dd = object.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            match kv {
                (b"e", val) => {
                    let mut elst = val.try_into_list().context("e")?;
                    if let Some(item) = elst.next_object().context("e")? {
                        error_code = Some(u32::decode_bencode_object(item).context("e.0")?);
                    }
                    if error_code.is_some() {
                        if let Some(item) = elst.next_object().context("e")? {
                            error_message = Some(
                                String::from_utf8_lossy(item.try_into_bytes().context("e.1")?)
                                    .into_owned(),
                            );
                        }
                    }
                }
                (b"t", val) => {
                    let data = AsString::<Vec<u8>>::decode_bencode_object(val).context("t")?;
                    transaction_id = Some(Bytes::from(data.0));
                }
                (b"v", val) => {
                    client = Some(
                        String::from_utf8_lossy(val.try_into_bytes().context("v")?).into_owned(),
                    );
                }
                (b"y", val) => {
                    let data = String::decode_bencode_object(val).context("y")?;
                    if data != "e" {
                        return Err(BendyError::malformed_content(InvalidYField {
                            expected: "e",
                            got: data,
                        })
                        .context("y"));
                    }
                }
                _ => (),
            }
        }
        let transaction_id = transaction_id.ok_or_else(|| BendyError::missing_field("t"))?;
        let error_code = error_code.ok_or_else(|| BendyError::missing_field("e.0"))?;
        let error_message = error_message.ok_or_else(|| BendyError::missing_field("e.1"))?;
        Ok(ErrorResponse {
            transaction_id,
            client,
            error_code,
            error_message,
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum RpcError {
    #[error("generic error: {0:?}")]
    Generic(String),
    #[error("server error: {0:?}")]
    Server(String),
    #[error("protocol error: {0:?}")]
    Protocol(String),
    #[error("method unknown error: {0:?}")]
    MethodUnknown(String),
    #[error("other error: code {code}: {message:?}")]
    Other { code: u32, message: String },
}

impl From<ErrorResponse> for RpcError {
    fn from(value: ErrorResponse) -> RpcError {
        match value.error_code {
            201 => RpcError::Generic(value.error_message),
            202 => RpcError::Server(value.error_message),
            203 => RpcError::Protocol(value.error_message),
            204 => RpcError::MethodUnknown(value.error_message),
            code => RpcError::Other {
                code,
                message: value.error_message,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NodeInfo {
    pub(super) id: NodeId,
    pub(super) ip: IpAddr,
    pub(super) port: u16,
}

impl From<NodeInfoV4> for NodeInfo {
    fn from(value: NodeInfoV4) -> NodeInfo {
        NodeInfo {
            id: value.id,
            ip: value.ip.into(),
            port: value.port,
        }
    }
}

impl From<NodeInfoV6> for NodeInfo {
    fn from(value: NodeInfoV6) -> NodeInfo {
        NodeInfo {
            id: value.id,
            ip: value.ip.into(),
            port: value.port,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeInfoV4 {
    id: NodeId,
    ip: Ipv4Addr,
    port: u16,
}

impl FromCompact for NodeInfoV4 {
    type Error = FromCompactError;

    fn from_compact(bs: &[u8]) -> Result<NodeInfoV4, FromCompactError> {
        let e = FromCompactError {
            ty: "NodeInfoV4",
            length: bs.len(),
        };
        let mut buf = TryBytes::from(bs);
        let id = buf.try_get::<NodeId>().map_err(|_| e)?;
        let ip = buf.try_get::<Ipv4Addr>().map_err(|_| e)?;
        let port = buf.try_get::<u16>().map_err(|_| e)?;
        buf.eof().map_err(|_| e)?;
        Ok(NodeInfoV4 { id, ip, port })
    }
}

impl_vec_fromcompact!(NodeInfoV4, 26);

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeInfoV6 {
    id: NodeId,
    ip: Ipv6Addr,
    port: u16,
}

impl FromCompact for NodeInfoV6 {
    type Error = FromCompactError;

    fn from_compact(bs: &[u8]) -> Result<NodeInfoV6, FromCompactError> {
        let e = FromCompactError {
            ty: "NodeInfoV6",
            length: bs.len(),
        };
        let mut buf = TryBytes::from(bs);
        let id = buf.try_get::<NodeId>().map_err(|_| e)?;
        let ip = buf.try_get::<Ipv6Addr>().map_err(|_| e)?;
        let port = buf.try_get::<u16>().map_err(|_| e)?;
        buf.eof().map_err(|_| e)?;
        Ok(NodeInfoV6 { id, ip, port })
    }
}

impl_vec_fromcompact!(NodeInfoV6, 38);

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

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("invalid \"y\" field in DHT RPC packet; expected {expected:?}, got {got:?}")]
struct InvalidYField {
    expected: &'static str,
    got: String,
}

pub(super) fn get_transaction_id(msg: &[u8]) -> Result<Bytes, BendyError> {
    let mut decoder = Decoder::new(msg);
    if let Some(obj) = decoder.next_object()? {
        let mut dd = obj.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            if let (b"t", val) = kv {
                let data = AsString::<Vec<u8>>::decode_bencode_object(val).context("t")?;
                return Ok(Bytes::from(data.0));
            }
        }
    }
    Err(BendyError::missing_field("t"))
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
            let msg = decode_bencode::<ErrorResponse>(
                b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee",
            )
            .unwrap();
            assert_eq!(
                msg,
                ErrorResponse {
                    transaction_id: Bytes::from(b"aa".as_slice()),
                    client: None,
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
                    transaction_id: Bytes::from(b"aa".as_slice()),
                    client: None,
                    node_id: NodeId::from(b"mnopqrstuvwxyz123456"),
                    your_addr: None,
                }
            );
        }

        #[test]
        fn ping_response_ipv4() {
            let msg = decode_bencode::<PingResponse>(
                b"d2:ip6:abcdef1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re",
            )
            .unwrap();
            assert_eq!(
                msg,
                PingResponse {
                    transaction_id: Bytes::from(b"aa".as_slice()),
                    client: None,
                    node_id: NodeId::from(b"mnopqrstuvwxyz123456"),
                    your_addr: Some("97.98.99.100:25958".parse().unwrap()),
                }
            );
        }

        #[test]
        fn ping_response_ipv6() {
            let msg = decode_bencode::<PingResponse>(
                b"d2:ip18:abcdefghijklmnopqr1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re",
            )
            .unwrap();
            assert_eq!(
                msg,
                PingResponse {
                    transaction_id: Bytes::from(b"aa".as_slice()),
                    client: None,
                    node_id: NodeId::from(b"mnopqrstuvwxyz123456"),
                    your_addr: Some(
                        "[6162:6364:6566:6768:696a:6b6c:6d6e:6f70]:29042"
                            .parse()
                            .unwrap()
                    ),
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
                    transaction_id: Bytes::from(b"aa".as_slice()),
                    client: None,
                    node_id: NodeId::from(b"0123456789abcdefghij"),
                    nodes: vec![NodeInfo {
                        id: NodeId::from(b"mnopqrstuvwxyz123456"),
                        ip: IpAddr::V4(Ipv4Addr::new(105, 105, 105, 105)),
                        port: 28784,
                    }],
                    nodes6: Vec::new(),
                    your_addr: None,
                }
            );
        }

        #[test]
        fn get_peers_response_values() {
            let msg = decode_bencode::<GetPeersResponse>(b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re").unwrap();
            assert_eq!(
                msg,
                GetPeersResponse {
                    transaction_id: Bytes::from(b"aa".as_slice()),
                    client: None,
                    node_id: NodeId::from(b"abcdefghij0123456789"),
                    values: vec![
                        "97.120.106.101:11893".parse().unwrap(),
                        "105.100.104.116:28269".parse().unwrap(),
                    ],
                    nodes: Vec::new(),
                    nodes6: Vec::new(),
                    token: Bytes::from(b"aoeusnth".as_slice()),
                    your_addr: None,
                }
            );
        }

        #[test]
        fn get_peers_response_ipv6_values() {
            let msg = decode_bencode::<GetPeersResponse>(b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u18:iiiiiiiiiiiiiiiippee1:t2:aa1:y1:re").unwrap();
            assert_eq!(
                msg,
                GetPeersResponse {
                    transaction_id: Bytes::from(b"aa".as_slice()),
                    client: None,
                    node_id: NodeId::from(b"abcdefghij0123456789"),
                    values: vec![
                        "97.120.106.101:11893".parse().unwrap(),
                        "[6969:6969:6969:6969:6969:6969:6969:6969]:28784"
                            .parse()
                            .unwrap(),
                    ],
                    nodes: Vec::new(),
                    nodes6: Vec::new(),
                    token: Bytes::from(b"aoeusnth".as_slice()),
                    your_addr: None,
                }
            );
        }

        #[test]
        fn get_peers_response_nodes() {
            let msg = decode_bencode::<GetPeersResponse>(b"d1:rd2:id20:abcdefghij01234567895:nodes26:mnopqrstuvwxyz123456iiiipp5:token8:aoeusnthe1:t2:aa1:y1:re").unwrap();
            assert_eq!(
                msg,
                GetPeersResponse {
                    transaction_id: Bytes::from(b"aa".as_slice()),
                    client: None,
                    node_id: NodeId::from(b"abcdefghij0123456789"),
                    values: Vec::new(),
                    nodes: vec![NodeInfo {
                        id: NodeId::from(b"mnopqrstuvwxyz123456"),
                        ip: IpAddr::V4(Ipv4Addr::new(105, 105, 105, 105)),
                        port: 28784,
                    }],
                    nodes6: Vec::new(),
                    token: Bytes::from(b"aoeusnth".as_slice()),
                    your_addr: None,
                }
            );
        }

        #[test]
        fn get_peers_response_nodes6() {
            let msg = decode_bencode::<GetPeersResponse>(b"d1:rd2:id20:abcdefghij01234567896:nodes638:mnopqrstuvwxyz123456iiiiiiiiiiiiiiiipp5:token8:aoeusnthe1:t2:aa1:y1:re").unwrap();
            assert_eq!(
                msg,
                GetPeersResponse {
                    transaction_id: Bytes::from(b"aa".as_slice()),
                    client: None,
                    node_id: NodeId::from(b"abcdefghij0123456789"),
                    values: Vec::new(),
                    nodes: Vec::new(),
                    nodes6: vec![NodeInfo {
                        id: NodeId::from(b"mnopqrstuvwxyz123456"),
                        ip: "6969:6969:6969:6969:6969:6969:6969:6969".parse().unwrap(),
                        port: 28784,
                    }],
                    token: Bytes::from(b"aoeusnth".as_slice()),
                    your_addr: None,
                }
            );
        }
    }

    mod encode {
        use super::*;

        #[test]
        fn ping_query() {
            let msg = PingQuery {
                transaction_id: Bytes::from(b"aa".as_slice()),
                client: None,
                node_id: NodeId::from(b"abcdefghij0123456789"),
                read_only: None,
            };
            assert_eq!(
                msg.to_bencode().unwrap(),
                b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe",
            );
        }

        #[test]
        fn find_node_query() {
            let msg = FindNodeQuery {
                transaction_id: Bytes::from(b"aa".as_slice()),
                client: None,
                node_id: NodeId::from(b"abcdefghij0123456789"),
                target: NodeId::from(b"mnopqrstuvwxyz123456"),
                read_only: None,
                want: None,
            };
            assert_eq!(msg.to_bencode().unwrap(), b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe");
        }

        #[test]
        fn get_peers_query() {
            let msg = GetPeersQuery {
                transaction_id: Bytes::from(b"aa".as_slice()),
                client: None,
                node_id: NodeId::from(b"abcdefghij0123456789"),
                info_hash: InfoHash::from(b"mnopqrstuvwxyz123456"),
                read_only: None,
                want: None,
            };
            assert_eq!(msg.to_bencode().unwrap(), b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");
        }

        #[test]
        fn get_peers_query_want_n4() {
            let msg = GetPeersQuery {
                transaction_id: Bytes::from(b"aa".as_slice()),
                client: None,
                node_id: NodeId::from(b"abcdefghij0123456789"),
                info_hash: InfoHash::from(b"mnopqrstuvwxyz123456"),
                read_only: None,
                want: Some(vec![Want::N4]),
            };
            assert_eq!(msg.to_bencode().unwrap(), b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:wantl2:n4ee1:q9:get_peers1:t2:aa1:y1:qe");
        }

        #[test]
        fn get_peers_query_want_n6() {
            let msg = GetPeersQuery {
                transaction_id: Bytes::from(b"aa".as_slice()),
                client: None,
                node_id: NodeId::from(b"abcdefghij0123456789"),
                info_hash: InfoHash::from(b"mnopqrstuvwxyz123456"),
                read_only: None,
                want: Some(vec![Want::N6]),
            };
            assert_eq!(msg.to_bencode().unwrap(), b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:wantl2:n6ee1:q9:get_peers1:t2:aa1:y1:qe");
        }

        #[test]
        fn get_peers_query_want_n4_n6() {
            let msg = GetPeersQuery {
                transaction_id: Bytes::from(b"aa".as_slice()),
                client: None,
                node_id: NodeId::from(b"abcdefghij0123456789"),
                info_hash: InfoHash::from(b"mnopqrstuvwxyz123456"),
                read_only: None,
                want: Some(vec![Want::N4, Want::N6]),
            };
            assert_eq!(msg.to_bencode().unwrap(), b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:wantl2:n42:n6ee1:q9:get_peers1:t2:aa1:y1:qe");
        }
    }

    mod get_transaction_id {
        use super::*;

        #[test]
        fn ok() {
            let t =
                get_transaction_id(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re".as_slice())
                    .unwrap();
            assert_eq!(t, b"aa".as_slice());
        }

        #[test]
        fn empty() {
            let e = get_transaction_id(b"".as_slice()).unwrap_err();
            assert_eq!(e.to_string(), "missing field: t");
        }

        #[test]
        fn no_t() {
            let e = get_transaction_id(b"d1:eli201e5:Ouch.e1:y1:ee".as_slice()).unwrap_err();
            assert_eq!(e.to_string(), "missing field: t");
        }

        #[test]
        fn not_dict() {
            let e = get_transaction_id(b"li201e5:Ouch.e".as_slice()).unwrap_err();
            assert_eq!(e.to_string(), "discovered List but expected Dict");
        }
    }
}
