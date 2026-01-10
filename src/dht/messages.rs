use super::{Node, NodeId};
use crate::compact::AsCompact;
use crate::peer::Peer;
use crate::types::InfoHash;
use crate::util::{UnbencodeError, decode_bencode};
use bendy::decoding::{Decoder, Error as BendyError, FromBencode, Object, ResultExt};
use bendy::encoding::{AsString, SingleItemEncoder, ToBencode};
use bytes::{BufMut, Bytes, BytesMut};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GetPeersQuery {
    pub(super) transaction_id: Bytes,
    pub(super) client: Option<Bytes>,
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
            if let Some(ro) = self.read_only {
                e.emit_pair(b"ro", u8::from(ro))?;
            }
            e.emit_pair(b"t", AsString(&self.transaction_id))?;
            if let Some(ref v) = self.client {
                e.emit_pair(b"v", AsString(v))?;
            }
            e.emit_pair(b"y", AsString(b"q"))?;
            Ok(())
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GetPeersResponse {
    pub(super) transaction_id: Bytes,
    pub(super) client: Option<Bytes>,
    pub(super) node_id: NodeId,
    pub(super) values: Vec<Peer>,
    pub(super) nodes: Vec<Node<Ipv4Addr>>,
    pub(super) nodes6: Vec<Node<Ipv6Addr>>,
    pub(super) token: Option<Bytes>,
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
                    let data = AsString::<Vec<u8>>::decode_bencode_object(val).context("v")?;
                    client = Some(Bytes::from(data.0));
                }
                (b"y", val) => {
                    let data = String::decode_bencode_object(val).context("y")?;
                    if data != "r" {
                        return Err(BendyError::malformed_content(InvalidYField {
                            expected: "\"r\"",
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
                                let ns =
                                    AsCompact::<Vec<Node<Ipv4Addr>>>::decode_bencode_object(rval)
                                        .context("r.nodes")?;
                                nodes.extend(ns.0);
                            }
                            (b"nodes6", rval) => {
                                let ns =
                                    AsCompact::<Vec<Node<Ipv6Addr>>>::decode_bencode_object(rval)
                                        .context("r.nodes6")?;
                                nodes6.extend(ns.0);
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
    pub(super) client: Option<Bytes>,
    pub(super) code: ErrorCode,
    pub(super) message: String,
    pub(super) your_addr: Option<SocketAddr>,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code, self.message)
    }
}

impl std::error::Error for ErrorResponse {}

impl FromBencode for ErrorResponse {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<ErrorResponse, BendyError> {
        let mut transaction_id = None;
        let mut client = None;
        let mut code = None;
        let mut message = None;
        let mut your_addr = None;
        let mut dd = object.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            match kv {
                (b"e", val) => {
                    let mut elst = val.try_into_list().context("e")?;
                    if let Some(item) = elst.next_object().context("e")? {
                        code = Some(ErrorCode::decode_bencode_object(item).context("e.0")?);
                    }
                    if code.is_some()
                        && let Some(item) = elst.next_object().context("e")?
                    {
                        message = Some(
                            String::from_utf8_lossy(item.try_into_bytes().context("e.1")?)
                                .into_owned(),
                        );
                    }
                }
                (b"t", val) => {
                    let data = AsString::<Vec<u8>>::decode_bencode_object(val).context("t")?;
                    transaction_id = Some(Bytes::from(data.0));
                }
                (b"v", val) => {
                    let data = AsString::<Vec<u8>>::decode_bencode_object(val).context("v")?;
                    client = Some(Bytes::from(data.0));
                }
                (b"y", val) => {
                    let data = String::decode_bencode_object(val).context("y")?;
                    if data != "e" {
                        return Err(BendyError::malformed_content(InvalidYField {
                            expected: "\"e\"",
                            got: data,
                        })
                        .context("y"));
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
        let code = code.ok_or_else(|| BendyError::missing_field("e.0"))?;
        let message = message.ok_or_else(|| BendyError::missing_field("e.1"))?;
        Ok(ErrorResponse {
            transaction_id,
            client,
            code,
            message,
            your_addr,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ErrorCode {
    Generic,
    Server,
    Protocol,
    MethodUnknown,
    Other(u32),
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::Generic => write!(f, "generic error"),
            ErrorCode::Server => write!(f, "server error"),
            ErrorCode::Protocol => write!(f, "protocol error"),
            ErrorCode::MethodUnknown => write!(f, "method unknown error"),
            ErrorCode::Other(code) => write!(f, "other error: code {code}"),
        }
    }
}

impl FromBencode for ErrorCode {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<ErrorCode, BendyError> {
        match u32::decode_bencode_object(object)? {
            201 => Ok(ErrorCode::Generic),
            202 => Ok(ErrorCode::Server),
            203 => Ok(ErrorCode::Protocol),
            204 => Ok(ErrorCode::MethodUnknown),
            code => Ok(ErrorCode::Other(code)),
        }
    }
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

pub(super) fn gen_client() -> Bytes {
    let mut buf = BytesMut::with_capacity(4);
    buf.put_u8(b'D');
    buf.put_u8(b'M');
    buf.put_u8(
        env!("CARGO_PKG_VERSION_MAJOR")
            .parse::<u8>()
            .unwrap_or(255u8),
    );
    buf.put_u8(
        env!("CARGO_PKG_VERSION_MINOR")
            .parse::<u8>()
            .unwrap_or(255u8),
    );
    buf.freeze()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Prescan {
    pub(super) transaction_id: Bytes,
    pub(super) msg_type: MessageType,
}

pub(super) fn prescan(msg: &[u8]) -> Result<Prescan, BendyError> {
    let mut decoder = Decoder::new(msg);
    let mut transaction_id = None;
    let mut msg_type = None;
    if let Some(obj) = decoder.next_object()? {
        let mut dd = obj.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            match kv {
                (b"t", val) => {
                    let data = AsString::<Vec<u8>>::decode_bencode_object(val).context("t")?;
                    transaction_id = Some(Bytes::from(data.0));
                }
                (b"y", val) => {
                    msg_type = Some(MessageType::decode_bencode_object(val).context("y")?);
                }
                _ => (),
            }
        }
    }
    let transaction_id = transaction_id.ok_or_else(|| BendyError::missing_field("t"))?;
    let msg_type = msg_type.ok_or_else(|| BendyError::missing_field("y"))?;
    Ok(Prescan {
        transaction_id,
        msg_type,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MessageType {
    Query,
    Response,
    Error,
}

impl FromBencode for MessageType {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<MessageType, BendyError> {
        let mt = String::decode_bencode_object(object)?;
        match mt.as_str() {
            "q" => Ok(MessageType::Query),
            "r" => Ok(MessageType::Response),
            "e" => Ok(MessageType::Error),
            _ => Err(BendyError::malformed_content(InvalidYField {
                expected: "\"r\", \"q\", or \"e\"",
                got: mt,
            })),
        }
    }
}

pub(super) fn decode_response<T: FromBencode>(msg: &[u8]) -> Result<T, ResponseError> {
    let mut msg_type = None;
    let mut decoder = Decoder::new(msg);
    if let Some(obj) = decoder.next_object()? {
        let mut dd = obj.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            if let (b"y", val) = kv {
                msg_type = Some(MessageType::decode_bencode_object(val).context("y")?);
                break;
            }
        }
    }
    match msg_type.ok_or_else(|| BendyError::missing_field("y"))? {
        MessageType::Response => decode_bencode::<T>(msg).map_err(Into::into),
        MessageType::Error => {
            let err = decode_bencode::<ErrorResponse>(msg)?;
            Err(ResponseError::Rpc(Box::new(err)))
        }
        MessageType::Query => Err(ResponseError::Query),
    }
}

#[derive(Clone, Debug, Error)]
pub(super) enum ResponseError {
    #[error("failed to decode DHT RPC packet")]
    Bencode(#[from] UnbencodeError),
    #[error("remote DHT node replied with error")]
    Rpc(#[from] Box<ErrorResponse>),
    #[error("failed to decode response from packet: is actually a query")]
    Query,
}

impl From<BendyError> for ResponseError {
    fn from(value: BendyError) -> ResponseError {
        ResponseError::from(UnbencodeError::from(value))
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("invalid \"y\" field in DHT RPC packet; expected {expected}, got {got:?}")]
pub(super) struct InvalidYField {
    expected: &'static str,
    got: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    mod decode {
        use super::*;
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
                    code: ErrorCode::Generic,
                    message: "A Generic Error Ocurred".into(),
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
                    token: Some(Bytes::from(b"aoeusnth".as_slice())),
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
                    token: Some(Bytes::from(b"aoeusnth".as_slice())),
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
                    nodes: vec![Node {
                        id: NodeId::from(b"mnopqrstuvwxyz123456"),
                        ip: Ipv4Addr::new(105, 105, 105, 105),
                        port: 28784,
                    }],
                    nodes6: Vec::new(),
                    token: Some(Bytes::from(b"aoeusnth".as_slice())),
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
                    nodes6: vec![Node {
                        id: NodeId::from(b"mnopqrstuvwxyz123456"),
                        ip: "6969:6969:6969:6969:6969:6969:6969:6969".parse().unwrap(),
                        port: 28784,
                    }],
                    token: Some(Bytes::from(b"aoeusnth".as_slice())),
                    your_addr: None,
                }
            );
        }
    }

    mod encode {
        use super::*;

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

        #[test]
        fn get_peers_query_all_fields() {
            let msg = GetPeersQuery {
                transaction_id: Bytes::from(b"xx".as_slice()),
                client: Some(Bytes::from(b"TEST".as_slice())),
                node_id: NodeId::from(b"abcdefghij0123456789"),
                info_hash: InfoHash::from(b"mnopqrstuvwxyz123456"),
                read_only: Some(true),
                want: Some(vec![Want::N4, Want::N6]),
            };
            assert_eq!(msg.to_bencode().unwrap(), b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz1234564:wantl2:n42:n6ee1:q9:get_peers2:roi1e1:t2:xx1:v4:TEST1:y1:qe");
        }
    }

    mod prescan {
        use super::*;

        #[test]
        fn ok_query() {
            let ps =
                prescan(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:qe".as_slice()).unwrap();
            assert_eq!(ps.transaction_id, b"aa".as_slice());
            assert_eq!(ps.msg_type, MessageType::Query);
        }

        #[test]
        fn ok_response() {
            let ps =
                prescan(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re".as_slice()).unwrap();
            assert_eq!(ps.transaction_id, b"aa".as_slice());
            assert_eq!(ps.msg_type, MessageType::Response);
        }

        #[test]
        fn ok_error() {
            let ps =
                prescan(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:ee".as_slice()).unwrap();
            assert_eq!(ps.transaction_id, b"aa".as_slice());
            assert_eq!(ps.msg_type, MessageType::Error);
        }

        #[test]
        fn empty() {
            let e = prescan(b"".as_slice()).unwrap_err();
            assert_eq!(e.to_string(), "missing field: t");
        }

        #[test]
        fn no_t() {
            let e = prescan(b"d1:eli201e5:Ouch.e1:y1:ee".as_slice()).unwrap_err();
            assert_eq!(e.to_string(), "missing field: t");
        }

        #[test]
        fn not_dict() {
            let e = prescan(b"li201e5:Ouch.e".as_slice()).unwrap_err();
            assert_eq!(e.to_string(), "discovered List but expected Dict");
        }

        #[test]
        fn no_y() {
            let e = prescan(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aae".as_slice()).unwrap_err();
            assert_eq!(e.to_string(), "missing field: y");
        }

        #[test]
        fn bad_y() {
            let e =
                prescan(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:xe".as_slice()).unwrap_err();
            assert_eq!(
                e.to_string(),
                "malformed content discovered: invalid \"y\" field in DHT RPC packet; expected \"r\", \"q\", or \"e\", got \"x\"\nin context:\n\ty"
            );
        }
    }

    mod decode_response {
        use super::*;
        use assert_matches::assert_matches;

        #[test]
        fn get_peers_response() {
            let msg = decode_response::<GetPeersResponse>(b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re").unwrap();
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
                    token: Some(Bytes::from(b"aoeusnth".as_slice())),
                    your_addr: None,
                }
            );
        }

        #[test]
        fn error() {
            let e = decode_response::<GetPeersResponse>(
                b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee",
            )
            .unwrap_err();
            assert_matches!(e, ResponseError::Rpc(ebox) => {
                assert_eq!(
                    *ebox,
                    ErrorResponse {
                        transaction_id: Bytes::from(b"aa".as_slice()),
                        client: None,
                        code: ErrorCode::Generic,
                        message: "A Generic Error Ocurred".into(),
                        your_addr: None,
                    }
                );
            });
        }

        #[test]
        fn query() {
            let e = decode_response::<GetPeersResponse>(
                b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe"
            )
            .unwrap_err();
            assert_matches!(e, ResponseError::Query);
        }
    }
}
