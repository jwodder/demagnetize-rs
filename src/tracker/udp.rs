use super::*;
use crate::util::TryBytes;
use bytes::{BufMut, Bytes, BytesMut};
use std::fmt;
use std::net::{SocketAddrV4, SocketAddrV6};
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UdpTracker(Url);

impl UdpTracker {
    pub(super) async fn connect(&self) -> Result<UdpTrackerSession<'_>, TrackerError> {
        todo!()
    }
}

impl fmt::Display for UdpTracker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<Tracker {}>", self.0)
    }
}

impl TryFrom<Url> for UdpTracker {
    type Error = TrackerUrlError;

    fn try_from(url: Url) -> Result<UdpTracker, TrackerUrlError> {
        let sch = url.scheme();
        if sch != "udp" {
            return Err(TrackerUrlError::UnsupportedScheme(sch.into()));
        }
        if url.host().is_none() {
            return Err(TrackerUrlError::NoHost);
        }
        if url.port().is_none() {
            return Err(TrackerUrlError::NoUdpPort);
        }
        Ok(UdpTracker(url))
    }
}

pub(super) struct UdpTrackerSession<'a> {
    pub(super) tracker: &'a UdpTracker,
    // ???
}

impl<'a> UdpTrackerSession<'a> {
    pub(super) async fn announce<'b>(
        &self,
        _announcement: Announcement<'b>,
    ) -> Result<AnnounceResponse, TrackerError> {
        todo!()
    }
}

const PROTOCOL_ID: u64 = 0x41727101980;
const CONNECT_ACTION: u32 = 0;
const ANNOUNCE_ACTION: u32 = 1;
const ERROR_ACTION: u32 = 3;

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
    type Error = TrackerError;

    fn try_from(buf: Bytes) -> Result<Self, TrackerError> {
        let mut buf = TryBytes::from(buf);
        let action = buf.try_get::<u32>()?;
        if action != CONNECT_ACTION {
            return Err(TrackerError::BadUdpAction {
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct UdpAnnounceRequest<'a> {
    connection_id: u64,
    transaction_id: u32,
    announcement: Announcement<'a>,
}

impl<'a> From<UdpAnnounceRequest<'a>> for Bytes {
    fn from(req: UdpAnnounceRequest<'a>) -> Bytes {
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
        buf.freeze()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UdpAnnounceResponse {
    transaction_id: u32,
    response: AnnounceResponse,
}

impl UdpAnnounceResponse {
    fn from_bytes(buf: Bytes, ipv6: bool) -> Result<Self, TrackerError> {
        raise_for_error(&buf)?;
        let mut buf = TryBytes::from(buf);
        let action = buf.try_get::<u32>()?;
        if action != ANNOUNCE_ACTION {
            return Err(TrackerError::BadUdpAction {
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

fn raise_for_error(buf: &Bytes) -> Result<(), TrackerError> {
    let mut view = TryBytes::from(buf.slice(0..));
    if view.try_get::<u32>() == Ok(ERROR_ACTION) {
        let _transaction_id = view.try_get::<u32>()?;
        // TODO: Should we bother to check the transaction ID?
        let message = view.into_string_lossy();
        Err(TrackerError::Failure(message))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_connection_request() {
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
    fn test_parse_connection_response() {
        let buf = Bytes::from(b"\x00\x00\x00\x00\\1\rs\\\xcb\xdf\xdb\x15|%\xba".as_slice());
        let res = UdpConnectionResponse::try_from(buf).unwrap();
        assert_eq!(res.transaction_id, 0x5C310D73);
        assert_eq!(res.connection_id, 0x5CCBDFDB157C25BA);
    }

    #[test]
    fn test_make_announce_request() {
        let req = UdpAnnounceRequest {
            connection_id: 0x5CCBDFDB157C25BA,
            transaction_id: 0xA537EEE7,
            announcement: Announcement {
                info_hash: &"4c3e215f9e50b06d708a74c9b0e66e08bce520aa"
                    .parse::<InfoHash>()
                    .unwrap(),
                peer_id: &PeerId::try_from(Bytes::from(b"-TR3000-12nig788rk3b".as_slice()))
                    .unwrap(),
                port: 60069,
                key: Key::from(0x2C545EDE),
                event: AnnounceEvent::Started,
                downloaded: 0,
                uploaded: 0,
                left: (1 << 63) - 1,
                numwant: 80,
            },
        };
        let buf = Bytes::from(req);
        assert_eq!(buf,
            b"\\\xcb\xdf\xdb\x15|%\xba\x00\x00\x00\x01\xa57\xee\xe7L>!_\x9eP\xb0mp\x8at\xc9\xb0\xe6n\x08\xbc\xe5 \xaa-TR3000-12nig788rk3b\x00\x00\x00\x00\x00\x00\x00\x00\x7f\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00,T^\xde\x00\x00\x00P\xea\xa5".as_slice()
        );
    }

    #[test]
    fn test_parse_announce_response_ipv4() {
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
    fn test_parse_announce_response_ipv6_not_all_peers() {
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
    fn test_parse_announce_response_ipv4_no_peers() {
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
