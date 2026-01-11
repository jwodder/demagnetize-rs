use super::{AnnounceResponse, Announcement, TrackerError, TrackerUrlError};
use crate::consts::UDP_PACKET_LEN;
use crate::peer::Peer;
use crate::util::{PacketError, TryBytes};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::random;
use std::fmt;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use thiserror::Error;
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::{Instant, timeout, timeout_at};
use url::Url;

const PROTOCOL_ID: u64 = 0x41727101980;
const CONNECT_ACTION: u32 = 0;
const ANNOUNCE_ACTION: u32 = 1;
const ERROR_ACTION: u32 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UdpTracker(UdpUrl);

impl UdpTracker {
    pub(crate) fn url_string(&self) -> String {
        self.0.to_string()
    }

    pub(super) async fn connect(&self) -> Result<UdpTrackerSession, TrackerError> {
        let socket = ConnectedUdpSocket::connect(&self.0.host, self.0.port).await?;
        Ok(UdpTrackerSession::new(self, socket))
    }
}

impl fmt::Display for UdpTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<Tracker {}>", self.0)
    }
}

impl TryFrom<Url> for UdpTracker {
    type Error = TrackerUrlError;

    fn try_from(url: Url) -> Result<UdpTracker, TrackerUrlError> {
        UdpUrl::try_from(url).map(UdpTracker)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UdpUrl {
    host: String,
    port: u16,
    urldata: String,
}

impl fmt::Display for UdpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "udp://")?;
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            write!(f, "{}", self.host)?;
        }
        write!(f, ":{}{}", self.port, self.urldata)?;
        Ok(())
    }
}

impl TryFrom<Url> for UdpUrl {
    type Error = TrackerUrlError;

    fn try_from(url: Url) -> Result<UdpUrl, TrackerUrlError> {
        let sch = url.scheme();
        if sch != "udp" {
            return Err(TrackerUrlError::UnsupportedScheme(sch.into()));
        }
        let host = match url.host() {
            Some(url::Host::Domain(s)) => s.to_owned(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            None => return Err(TrackerUrlError::NoHost),
        };
        let Some(port) = url.port() else {
            return Err(TrackerUrlError::NoUdpPort);
        };
        let mut urldata = String::from(url.path());
        if let Some(query) = url.query() {
            urldata.push('?');
            urldata.push_str(query);
        }
        Ok(UdpUrl {
            host,
            port,
            urldata,
        })
    }
}

pub(super) struct UdpTrackerSession {
    pub(super) tracker: UdpTracker,
    socket: ConnectedUdpSocket,
    conn: Option<Connection>,
}

impl UdpTrackerSession {
    fn new(tracker: &UdpTracker, socket: ConnectedUdpSocket) -> Self {
        UdpTrackerSession {
            tracker: tracker.clone(),
            socket,
            conn: None,
        }
    }

    pub(super) async fn announce(
        &mut self,
        announcement: Announcement,
    ) -> Result<AnnounceResponse, TrackerError> {
        loop {
            let conn = self.get_connection().await?;
            let transaction_id = self.make_transaction_id();
            let msg = Bytes::from(UdpAnnounceRequest {
                connection_id: conn.id,
                transaction_id,
                announcement: announcement.clone(),
                urldata: self.tracker.0.urldata.clone(),
            });
            // TODO: Should communication be retried on parse errors and
            // mismatched transaction IDs?
            let resp = match timeout_at(conn.expiration, self.chat(msg)).await {
                Ok(Ok(buf)) => Response::<UdpAnnounceResponse>::from_bytes(buf, |buf| {
                    UdpAnnounceResponse::from_bytes(buf, self.socket.ipv6)
                })?
                .ok()?,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => {
                    log::trace!("Connection to {} timed out; restarting", self.tracker);
                    self.reset_connection();
                    continue;
                }
            };
            if resp.transaction_id != transaction_id {
                return Err(UdpTrackerError::XactionMismatch {
                    expected: transaction_id,
                    got: resp.transaction_id,
                }
                .into());
            }
            return Ok(resp.response);
        }
    }

    async fn get_connection(&mut self) -> Result<Connection, TrackerError> {
        if let Some(c) = self.conn {
            if Instant::now() < c.expiration {
                return Ok(c);
            } else {
                log::trace!("Connection to {} expired; will reconnect", self.tracker);
            }
        }
        let conn = self.connect().await?;
        self.conn = Some(conn);
        Ok(conn)
    }

    fn reset_connection(&mut self) {
        self.conn = None;
    }

    async fn connect(&self) -> Result<Connection, TrackerError> {
        log::trace!("Sending connection request to {}", self.tracker);
        let transaction_id = self.make_transaction_id();
        let msg = Bytes::from(UdpConnectionRequest { transaction_id });
        let raw_resp = self.chat(msg).await?;
        // TODO: Should communication be retried on parse errors and mismatched
        // transaction IDs?
        let resp = Response::<UdpConnectionResponse>::from_bytes(raw_resp, |buf| {
            UdpConnectionResponse::try_from(buf)
        })?
        .ok()?;
        if resp.transaction_id != transaction_id {
            return Err(UdpTrackerError::XactionMismatch {
                expected: transaction_id,
                got: resp.transaction_id,
            }
            .into());
        }
        log::trace!("Connected to {}", self.tracker);
        let expiration = Instant::now() + Duration::from_secs(60);
        Ok(Connection {
            id: resp.connection_id,
            expiration,
        })
    }

    async fn chat(&self, msg: Bytes) -> Result<Bytes, UdpTrackerError> {
        let mut n = 0;
        loop {
            self.socket.send(&msg).await?;
            let maxtime = Duration::from_secs(15 << n);
            if let Ok(r) = timeout(maxtime, self.socket.recv()).await {
                return r;
            } else {
                log::trace!("{} did not reply in time; resending message", self.tracker);
                if n < 8 {
                    // TODO: Should this count remember timeouts from previous
                    // connections & connection attempts?
                    n += 1;
                }
                continue;
            }
        }
    }

    fn make_transaction_id(&self) -> u32 {
        random()
    }
}

struct ConnectedUdpSocket {
    inner: UdpSocket,
    ipv6: bool,
}

impl ConnectedUdpSocket {
    async fn connect(host: &str, port: u16) -> Result<ConnectedUdpSocket, UdpTrackerError> {
        let Some(addr) = lookup_host((host, port))
            .await
            .map_err(UdpTrackerError::Lookup)?
            .next()
        else {
            return Err(UdpTrackerError::NoResolve);
        };
        let (bindaddr, ipv6) = match addr {
            SocketAddr::V4(_) => ("0.0.0.0:0", false),
            SocketAddr::V6(_) => ("[::]:0", true),
        };
        let socket = UdpSocket::bind(bindaddr)
            .await
            .map_err(UdpTrackerError::Bind)?;
        log::trace!(
            "Connected UDP socket to {} (IP address: {}), port {}",
            host,
            addr.ip(),
            port,
        );
        socket
            .connect(addr)
            .await
            .map_err(UdpTrackerError::Connect)?;
        Ok(ConnectedUdpSocket {
            inner: socket,
            ipv6,
        })
    }

    async fn send(&self, msg: &Bytes) -> Result<(), UdpTrackerError> {
        self.inner.send(msg).await.map_err(UdpTrackerError::Send)?;
        Ok(())
    }

    async fn recv(&self) -> Result<Bytes, UdpTrackerError> {
        let mut buf = BytesMut::with_capacity(UDP_PACKET_LEN);
        self.inner
            .recv_buf(&mut buf)
            .await
            .map_err(UdpTrackerError::Recv)?;
        Ok(buf.freeze())
    }
}

// UDP tracker psuedo-connection (BEP 15)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Connection {
    id: u64,
    expiration: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Response<T> {
    Success(T),
    Failure(String),
}

impl<T> Response<T> {
    fn ok(self) -> Result<T, TrackerError> {
        match self {
            Response::Success(res) => Ok(res),
            Response::Failure(msg) => Err(TrackerError::Failure(msg)),
        }
    }

    fn from_bytes<F>(buf: Bytes, parser: F) -> Result<Self, UdpTrackerError>
    where
        F: FnOnce(Bytes) -> Result<T, UdpTrackerError>,
    {
        let mut view = TryBytes::from(buf.slice(0..));
        if view.try_get::<u32>() == Ok(ERROR_ACTION) {
            let _transaction_id = view.try_get::<u32>()?;
            // TODO: Should we bother to check the transaction ID?
            let message = view.into_string_lossy();
            Ok(Response::Failure(message))
        } else {
            parser(buf).map(Response::Success)
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct UdpConnectionRequest {
    transaction_id: u32,
}

impl From<UdpConnectionRequest> for Bytes {
    fn from(req: UdpConnectionRequest) -> Bytes {
        let mut buf = BytesMut::with_capacity(16);
        buf.put_u64(PROTOCOL_ID);
        buf.put_u32(CONNECT_ACTION);
        buf.put_u32(req.transaction_id);
        buf.freeze()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct UdpConnectionResponse {
    transaction_id: u32,
    connection_id: u64,
}

impl TryFrom<Bytes> for UdpConnectionResponse {
    type Error = UdpTrackerError;

    fn try_from(buf: Bytes) -> Result<Self, UdpTrackerError> {
        let mut buf = TryBytes::from(buf);
        let action = buf.try_get::<u32>()?;
        if action != CONNECT_ACTION {
            return Err(UdpTrackerError::BadAction {
                expected: CONNECT_ACTION,
                got: action,
            });
        }
        let transaction_id = buf.try_get::<u32>()?;
        let connection_id = buf.try_get::<u64>()?;
        // Don't require EOF here, as "Clients ... should not assume packets to
        // be of a certain size"
        Ok(UdpConnectionResponse {
            transaction_id,
            connection_id,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UdpAnnounceRequest {
    connection_id: u64,
    transaction_id: u32,
    announcement: Announcement,
    urldata: String,
}

impl From<UdpAnnounceRequest> for Bytes {
    fn from(req: UdpAnnounceRequest) -> Bytes {
        let mut buf = BytesMut::with_capacity(98);
        buf.put_u64(req.connection_id);
        buf.put_u32(ANNOUNCE_ACTION);
        buf.put_u32(req.transaction_id);
        buf.put(req.announcement.info_hash.as_bytes());
        buf.put(req.announcement.peer_id.as_bytes());
        buf.put_u64(req.announcement.downloaded);
        buf.put_u64(req.announcement.left);
        buf.put_u64(req.announcement.uploaded);
        buf.put_u32(req.announcement.event.for_udp());
        buf.put_u32(0); // IP address
        buf.put_u32(req.announcement.key.into());
        buf.put_u32(req.announcement.numwant);
        buf.put_u16(req.announcement.port);
        // BEP 41:
        let mut urldata = Bytes::from(req.urldata.into_bytes());
        while urldata.has_remaining() {
            buf.put_u8(2);
            let segment = urldata.split_to(urldata.len().min(255));
            buf.put_u8(
                u8::try_from(segment.len())
                    .expect("segment length is no more than 255 and thus should fit in a u8"),
            );
            buf.put(segment);
        }
        buf.freeze()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UdpAnnounceResponse {
    transaction_id: u32,
    response: AnnounceResponse,
}

impl UdpAnnounceResponse {
    fn from_bytes(buf: Bytes, ipv6: bool) -> Result<Self, UdpTrackerError> {
        let mut buf = TryBytes::from(buf);
        let action = buf.try_get::<u32>()?;
        if action != ANNOUNCE_ACTION {
            return Err(UdpTrackerError::BadAction {
                expected: ANNOUNCE_ACTION,
                got: action,
            });
        }
        let transaction_id = buf.try_get::<u32>()?;
        let interval = buf.try_get::<u32>()?;
        let leechers = buf.try_get::<u32>()?;
        let seeders = buf.try_get::<u32>()?;
        // Despite what BEP 15 says about packets not having definite sizes, it
        // seems the only way to extract the peers from an announce response is
        // to read all addresses to the end of the packet.
        let peers = if ipv6 {
            buf.try_get_all::<SocketAddrV6>()?
                .into_iter()
                .map(Peer::from)
                .collect()
        } else {
            buf.try_get_all::<SocketAddrV4>()?
                .into_iter()
                .map(Peer::from)
                .collect()
        };
        Ok(UdpAnnounceResponse {
            transaction_id,
            response: AnnounceResponse {
                interval,
                peers,
                warning_message: None,
                min_interval: None,
                tracker_id: None,
                complete: None,
                incomplete: None,
                leechers: Some(leechers),
                seeders: Some(seeders),
            },
        })
    }
}

#[derive(Debug, Error)]
pub(crate) enum UdpTrackerError {
    #[error("failed to resolve remote hostname")]
    Lookup(#[source] std::io::Error),
    #[error("remote hostname did not resolve to any IP addresses")]
    NoResolve,
    #[error("failed to bind UDP socket")]
    Bind(#[source] std::io::Error),
    #[error("failed to connect UDP socket")]
    Connect(#[source] std::io::Error),
    #[error("failed to send UDP packet")]
    Send(#[source] std::io::Error),
    #[error("failed to receive UDP packet")]
    Recv(#[source] std::io::Error),
    #[error("UDP tracker sent response with invalid length")]
    PacketLen(#[from] PacketError),
    #[error(
        "UDP tracker sent response with unexpected or unsupported action; expected {expected}, got {got}"
    )]
    BadAction { expected: u32, got: u32 },
    #[error(
        "response from UDP tracker did not contain expected transaction ID; expected {expected:#x}, got {got:#x}"
    )]
    XactionMismatch { expected: u32, got: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracker::{AnnounceEvent, TrackerCrypto};
    use crate::types::{InfoHash, Key, PeerId};

    mod udp_url {
        use super::*;

        #[test]
        fn from_url() {
            let url = "udp://tracker.opentrackr.org:1337/announce"
                .parse::<Url>()
                .unwrap();
            let uu = UdpUrl::try_from(url).unwrap();
            assert_eq!(
                uu,
                UdpUrl {
                    host: "tracker.opentrackr.org".into(),
                    port: 1337,
                    urldata: "/announce".into(),
                }
            );
            assert_eq!(uu.to_string(), "udp://tracker.opentrackr.org:1337/announce");
        }

        #[test]
        fn from_url_no_urldata() {
            let url = "udp://tracker.opentrackr.org:1337".parse::<Url>().unwrap();
            let uu = UdpUrl::try_from(url).unwrap();
            assert_eq!(
                uu,
                UdpUrl {
                    host: "tracker.opentrackr.org".into(),
                    port: 1337,
                    urldata: String::new(),
                }
            );
            assert_eq!(uu.to_string(), "udp://tracker.opentrackr.org:1337");
        }

        #[test]
        fn from_url_ipv4() {
            let url = "udp://192.168.1.2:1337/announce".parse::<Url>().unwrap();
            let uu = UdpUrl::try_from(url).unwrap();
            assert_eq!(
                uu,
                UdpUrl {
                    host: "192.168.1.2".into(),
                    port: 1337,
                    urldata: "/announce".into(),
                }
            );
            assert_eq!(uu.to_string(), "udp://192.168.1.2:1337/announce");
        }

        #[test]
        fn from_url_ipv6() {
            let url = "udp://[3fff::abcd]:1337/announce".parse::<Url>().unwrap();
            let uu = UdpUrl::try_from(url).unwrap();
            assert_eq!(
                uu,
                UdpUrl {
                    host: "3fff::abcd".into(),
                    port: 1337,
                    urldata: "/announce".into(),
                }
            );
            assert_eq!(uu.to_string(), "udp://[3fff::abcd]:1337/announce");
        }
    }

    #[test]
    fn build_connection_request() {
        let req = UdpConnectionRequest {
            transaction_id: 0x5C310D73,
        };
        let buf = Bytes::from(req);
        assert_eq!(
            buf,
            b"\x00\x00\x04\x17'\x10\x19\x80\x00\x00\x00\x00\\1\rs".as_slice()
        );
    }

    #[test]
    fn parse_connection_response() {
        let buf = Bytes::from(b"\x00\x00\x00\x00\\1\rs\\\xcb\xdf\xdb\x15|%\xba".as_slice());
        let res = UdpConnectionResponse::try_from(buf).unwrap();
        assert_eq!(res.transaction_id, 0x5C310D73);
        assert_eq!(res.connection_id, 0x5CCBDFDB157C25BA);
    }

    #[test]
    fn build_announce_request() {
        let req = UdpAnnounceRequest {
            connection_id: 0x5CCBDFDB157C25BA,
            transaction_id: 0xA537EEE7,
            announcement: Announcement {
                info_hash: "4c3e215f9e50b06d708a74c9b0e66e08bce520aa"
                    .parse::<InfoHash>()
                    .unwrap(),
                peer_id: PeerId::from(b"-TR3000-12nig788rk3b"),
                port: 60069,
                key: Key::from(0x2C545EDE),
                event: AnnounceEvent::Started,
                downloaded: 0,
                uploaded: 0,
                left: (1 << 63) - 1,
                numwant: 80,
                crypto: TrackerCrypto::default(),
            },
            urldata: String::new(),
        };
        let buf = Bytes::from(req);
        assert_eq!(buf,
            b"\\\xcb\xdf\xdb\x15|%\xba\x00\x00\x00\x01\xa57\xee\xe7L>!_\x9eP\xb0mp\x8at\xc9\xb0\xe6n\x08\xbc\xe5 \xaa-TR3000-12nig788rk3b\x00\x00\x00\x00\x00\x00\x00\x00\x7f\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00,T^\xde\x00\x00\x00P\xea\xa5".as_slice()
        );
    }

    #[test]
    fn build_announce_request_urldata() {
        let req = UdpAnnounceRequest {
            connection_id: 0x5CCBDFDB157C25BA,
            transaction_id: 0xA537EEE7,
            announcement: Announcement {
                info_hash: "4c3e215f9e50b06d708a74c9b0e66e08bce520aa"
                    .parse::<InfoHash>()
                    .unwrap(),
                peer_id: PeerId::from(b"-TR3000-12nig788rk3b"),
                port: 60069,
                key: Key::from(0x2C545EDE),
                event: AnnounceEvent::Started,
                downloaded: 0,
                uploaded: 0,
                left: (1 << 63) - 1,
                numwant: 80,
                crypto: TrackerCrypto::default(),
            },
            urldata: "/announce".into(),
        };
        let buf = Bytes::from(req);
        assert_eq!(buf,
            b"\\\xcb\xdf\xdb\x15|%\xba\x00\x00\x00\x01\xa57\xee\xe7L>!_\x9eP\xb0mp\x8at\xc9\xb0\xe6n\x08\xbc\xe5 \xaa-TR3000-12nig788rk3b\x00\x00\x00\x00\x00\x00\x00\x00\x7f\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00,T^\xde\x00\x00\x00P\xea\xa5\x02\x09/announce".as_slice()
        );
    }

    #[test]
    fn parse_announce_response_ipv4() {
        let buf = Bytes::from(b"\x00\x00\x00\x01\xa57\xee\xe7\x00\x00\x07\x08\x00\x00\x00\x03\x00\x00\x00\x1a\x17Qr\xeb\xc9,\xbfe\xfe\xe0`\x07\xb9\x15\xd8\x95\t\x84\x9a\x15rd\x8f\xfe\xd5\x98\xbb\xebH\xda\xb2\x9b\x8b\xa8\x88\xb7\xc3N6\xd3\x7f\xa4\xacbGNV\xe1\xb0\x7f\xe6\xc6)\xaa\xd4f%\xba\xca\x7f\xa0\xb2\xbc\xcb\x1a\xe1\xb9\x15\xd8\x86\x80\x163\x0fh\xca8L]#\x92\xd4CB.\xf6\x03\xcd\xe3\xaa\xb9\x15\xd9M\xe1\x06V`\\\xe5\xc8\xd5Q\x06'\x9b\xc8\xd5\xb9A\x87\xb1\xe7\xb7N\x89\x17\x16M\xfc\xc1\x13\xce/\x1a\xe1\xb9&\x0e\xbf\xc64_\xf5l\xfd\xe1w\xb9\x99\xb3<\xf20\x99\xa2D\x9b\xea\xa5W\xf9\x86\x13\xd8\xb2\x9a\r\x01\x87\xc8\xd5\xb9\x9f\x9e9\x82\x1a\x8a\xc77%\x97S".as_slice());
        let res = UdpAnnounceResponse::from_bytes(buf, false).unwrap();
        assert_eq!(res.transaction_id, 0xA537EEE7);
        assert_eq!(res.response.interval, 1800);
        assert_eq!(res.response.leechers, Some(3));
        assert_eq!(res.response.seeders, Some(26));
        assert_eq!(
            res.response.peers,
            [
                "23.81.114.235:51500".parse::<Peer>().unwrap(),
                "191.101.254.224:24583".parse::<Peer>().unwrap(),
                "185.21.216.149:2436".parse::<Peer>().unwrap(),
                "154.21.114.100:36862".parse::<Peer>().unwrap(),
                "213.152.187.235:18650".parse::<Peer>().unwrap(),
                "178.155.139.168:34999".parse::<Peer>().unwrap(),
                "195.78.54.211:32676".parse::<Peer>().unwrap(),
                "172.98.71.78:22241".parse::<Peer>().unwrap(),
                "176.127.230.198:10666".parse::<Peer>().unwrap(),
                "212.102.37.186:51839".parse::<Peer>().unwrap(),
                "160.178.188.203:6881".parse::<Peer>().unwrap(),
                "185.21.216.134:32790".parse::<Peer>().unwrap(),
                "51.15.104.202:14412".parse::<Peer>().unwrap(),
                "93.35.146.212:17218".parse::<Peer>().unwrap(),
                "46.246.3.205:58282".parse::<Peer>().unwrap(),
                "185.21.217.77:57606".parse::<Peer>().unwrap(),
                "86.96.92.229:51413".parse::<Peer>().unwrap(),
                "81.6.39.155:51413".parse::<Peer>().unwrap(),
                "185.65.135.177:59319".parse::<Peer>().unwrap(),
                "78.137.23.22:19964".parse::<Peer>().unwrap(),
                "193.19.206.47:6881".parse::<Peer>().unwrap(),
                "185.38.14.191:50740".parse::<Peer>().unwrap(),
                "95.245.108.253:57719".parse::<Peer>().unwrap(),
                "185.153.179.60:62000".parse::<Peer>().unwrap(),
                "153.162.68.155:60069".parse::<Peer>().unwrap(),
                "87.249.134.19:55474".parse::<Peer>().unwrap(),
                "154.13.1.135:51413".parse::<Peer>().unwrap(),
                "185.159.158.57:33306".parse::<Peer>().unwrap(),
                "138.199.55.37:38739".parse::<Peer>().unwrap(),
            ]
        );
        assert_eq!(res.response.warning_message, None);
        assert_eq!(res.response.min_interval, None);
        assert_eq!(res.response.tracker_id, None);
        assert_eq!(res.response.complete, None);
        assert_eq!(res.response.incomplete, None);
    }

    #[test]
    fn parse_announce_response_ipv6_not_all_peers() {
        let mut buf = BytesMut::new();
        buf.put(b"\x00\x00\x00\x01\r\rY\x00\x00\x00\x077\x00\x00\x00\x06\x00".as_slice());
        buf.put(b"\x00\x00\x8f&\x07\xfe\xa8t\x97\x18\x00\x00\x00\x00\x00\x00".as_slice());
        buf.put(b"\x00^\x02'#&\x07\xfe\xa8t\x97\x18\x00\xd6\x9fs\xa0\xa0\x92".as_slice());
        buf.put(b"\xe9('#&\x07\xfe\xa8t\x97\x18\x00\xfc\x8d\n1\xad\x06 S'#*".as_slice());
        buf.put(b"\x01\x04\xf8\x01\n\x10\x88\x00\x00\x00\x00\x00\x00\x00\x02".as_slice());
        buf.put(b"\x93(*\x01\x0e\n\x02jzp\x9f\x04\x9c\x999\xfb\xb5\x12\xaeV*".as_slice());
        buf.put(b"\x01\x0e\n\x02jzp\xed\x9c\\j\x84\xa3\xfe\x92\xaeV*\x01\x0e".as_slice());
        buf.put(b"\n\n{a\x10\xf8\xa5\r\xadG\x87\xe8\xea\x10,*\x01\xcb\x08\x87".as_slice());
        buf.put(b"\xfb\x84\x00\x90\x1b<\xfd(-\x9cJ\xe1\x1a*\x01\xcb\x08\x87".as_slice());
        buf.put(b"\xfb\x84\x00\xe1Wa\xe9d\xfa9#\xe1\x1a*\x02\x06\xf8  \x01".as_slice());
        buf.put(b"\x97\x00\x02\x00\x00\x00\x00\x10\x08\xd0\xae*\x03\x1b \x00".as_slice());
        buf.put(b"\n\xf0\x11\x00\x00\x00\x00\x00\x00\xa0N\xf5\xd8$\x04\x0e".as_slice());
        buf.put(b"\x80nk\x00\x00\x1e\xda\xa3\xef\xe5\xd4\xcc\xd7\xa6t$\x04".as_slice());
        buf.put(b"\x0e\x80nk\x00\x00\x92\xa4>;L\x86\x15:\xa6t$\x04\x0e\x80nk".as_slice());
        buf.put(b"\x00\x00\xe7Q\x94j\xff,\x82\xef\xa6t&\x00\x17\x00:\xe8\x06".as_slice());
        buf.put(b"\x00\x00\x00\x00\x00\x00\x00\x00I\x82\xa2&\x00\x17\x00:\xe8".as_slice());
        buf.put(b"\x06\x00\x00\x8c9(\xe7\x159\xa4\x82\xa2&\x00\x17\x00:\xe8".as_slice());
        buf.put(b"\x06\x005\x11\xf1\x83\xcfb\xb7\xa2\x82\xa2&\x00\x17\x00:".as_slice());
        buf.put(b"\xe8\x06\x00\xd4Cl\xf4\xf0Z\xaa(\x82\xa2&\x04=\t }7\x00\x00".as_slice());
        buf.put(b"\x00\x00\x00\x00\x00mP\xed4&\x04=\t }7\x00B\xef.\x1d\xden".as_slice());
        buf.put(b"\xa5\x02\xed4&\x04\xa8\x80\x08\x00\x00\x10\x00\x00\x00\x00".as_slice());
        buf.put(b"\x01\xcc\xc0\x016Y&\x04\xa8\x80\x08\x00\x00\x10\x00\x00\x00".as_slice());
        buf.put(b"\x00\x01\xcc\xc0\x01\x8bZ&\x04\xa8\x80\x08\x00\x00\x10\x00".as_slice());
        buf.put(b"\x00\x00\x00\x01\xcc\xc0\x01\xac\xe0".as_slice());
        let res = UdpAnnounceResponse::from_bytes(buf.freeze(), true).unwrap();
        assert_eq!(res.transaction_id, 0x0D0D5900);
        assert_eq!(res.response.interval, 1847);
        assert_eq!(res.response.leechers, Some(6));
        assert_eq!(res.response.seeders, Some(143));
        assert_eq!(res.response.peers.len(), 23);
        assert_eq!(res.response.warning_message, None);
        assert_eq!(res.response.min_interval, None);
        assert_eq!(res.response.tracker_id, None);
        assert_eq!(res.response.complete, None);
        assert_eq!(res.response.incomplete, None);
    }

    #[test]
    fn parse_announce_response_ipv4_no_peers() {
        let buf = Bytes::from(
            b"\x00\x00\x00\x01\x13Tg\xd1\x00\x00\x07O\x00\x00\x00\x01\x00\x00\x00\x1d".as_slice(),
        );
        let res = UdpAnnounceResponse::from_bytes(buf, false).unwrap();
        assert_eq!(res.transaction_id, 0x135467D1);
        assert_eq!(res.response.interval, 1871);
        assert_eq!(res.response.leechers, Some(1));
        assert_eq!(res.response.seeders, Some(29));
        assert_eq!(res.response.peers, Vec::new());
        assert_eq!(res.response.warning_message, None);
        assert_eq!(res.response.min_interval, None);
        assert_eq!(res.response.tracker_id, None);
        assert_eq!(res.response.complete, None);
        assert_eq!(res.response.incomplete, None);
    }
}
