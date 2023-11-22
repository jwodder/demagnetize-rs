use super::*;
use crate::util::{decode_bencode, TryBytes, UnbencodeError};
use bendy::decoding::{Error as BendyError, FromBencode, Object, ResultExt};
use reqwest::Client;
use std::fmt;
use std::net::{SocketAddrV4, SocketAddrV6};
use thiserror::Error;
use url::Url;

static USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("CARGO_PKG_REPOSITORY"),
    ")",
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HttpTracker(Url);

impl HttpTracker {
    pub(crate) fn url_str(&self) -> &str {
        self.0.as_str()
    }

    pub(super) fn connect(&self) -> Result<HttpTrackerSession, TrackerError> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .build()
            .map_err(HttpTrackerError::BuildClient)?;
        Ok(HttpTrackerSession {
            tracker: self.clone(),
            client,
        })
    }
}

impl fmt::Display for HttpTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<Tracker {}>", self.0)
    }
}

impl TryFrom<Url> for HttpTracker {
    type Error = TrackerUrlError;

    fn try_from(url: Url) -> Result<HttpTracker, TrackerUrlError> {
        let sch = url.scheme();
        if sch != "http" && sch != "https" {
            return Err(TrackerUrlError::UnsupportedScheme(sch.into()));
        }
        if url.host().is_none() {
            return Err(TrackerUrlError::NoHost);
        }
        Ok(HttpTracker(url))
    }
}

pub(super) struct HttpTrackerSession {
    pub(super) tracker: HttpTracker,
    client: Client,
}

impl HttpTrackerSession {
    pub(super) async fn announce(
        &self,
        announcement: Announcement,
    ) -> Result<AnnounceResponse, TrackerError> {
        let mut url = self.tracker.0.clone();
        url.set_fragment(None);
        announcement.event.add_query_param(&mut url);
        announcement.info_hash.add_query_param(&mut url);
        announcement.peer_id.add_query_param(&mut url);
        url.query_pairs_mut()
            .append_pair("port", &announcement.port.to_string())
            .append_pair("uploaded", &announcement.uploaded.to_string())
            .append_pair("downloaded", &announcement.downloaded.to_string())
            .append_pair("left", &announcement.left.to_string())
            .append_pair("numwant", &announcement.numwant.to_string())
            .append_pair("key", &announcement.key.to_string())
            .append_pair("compact", "1");
        let buf = self
            .client
            .get(url)
            .send()
            .await
            .map_err(HttpTrackerError::SendRequest)?
            .error_for_status()
            .map_err(HttpTrackerError::HttpStatus)?
            .bytes()
            .await
            .map_err(HttpTrackerError::ReadBody)?;
        decode_bencode::<HttpAnnounceResponse>(&buf)
            .map_err(HttpTrackerError::ParseResponse)?
            .result()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HttpAnnounceResponse {
    Success(AnnounceResponse),
    Failure(String),
}

impl HttpAnnounceResponse {
    fn result(self) -> Result<AnnounceResponse, TrackerError> {
        match self {
            HttpAnnounceResponse::Success(announcement) => Ok(announcement),
            HttpAnnounceResponse::Failure(msg) => Err(TrackerError::Failure(msg)),
        }
    }
}

impl FromBencode for HttpAnnounceResponse {
    fn decode_bencode_object(object: Object<'_, '_>) -> Result<Self, BendyError> {
        let mut interval = None;
        let mut peers = Vec::new();
        let mut warning_message = None;
        let mut min_interval = None;
        let mut tracker_id = None;
        let mut complete = None;
        let mut incomplete = None;
        let mut dd = object.try_into_dictionary()?;
        while let Some(kv) = dd.next_pair()? {
            match kv {
                (b"failure reason", v) => {
                    let reason =
                        String::from_utf8_lossy(v.try_into_bytes().context("failure reason")?)
                            .into_owned();
                    return Ok(HttpAnnounceResponse::Failure(reason));
                }
                (b"interval", v) => {
                    interval = Some(u32::decode_bencode_object(v).context("interval")?);
                }
                (b"peers", v) => {
                    if matches!(v, Object::List(_)) {
                        // Original, non-compact format (BEP 3)
                        peers.extend(Vec::<Peer>::decode_bencode_object(v).context("peers")?);
                    } else {
                        // Compact format (BEP 23)
                        let buf = TryBytes::from(v.try_into_bytes().context("peers")?);
                        let addrs = match buf.try_get_all::<SocketAddrV4>() {
                            Ok(addrs) => addrs,
                            Err(e) => {
                                return Err(
                                    BendyError::malformed_content(Box::new(e)).context("peers")
                                );
                            }
                        };
                        peers.extend(addrs.into_iter().map(Peer::from));
                    }
                }
                (b"peers6", v) => {
                    // Compact format (BEP 7)
                    let buf = TryBytes::from(v.try_into_bytes().context("peers6")?);
                    let addrs = match buf.try_get_all::<SocketAddrV6>() {
                        Ok(addrs) => addrs,
                        Err(e) => {
                            return Err(
                                BendyError::malformed_content(Box::new(e)).context("peers6")
                            );
                        }
                    };
                    peers.extend(addrs.into_iter().map(Peer::from));
                }
                (b"warning message", v) => {
                    warning_message = Some(
                        String::from_utf8_lossy(v.try_into_bytes().context("warning message")?)
                            .into_owned(),
                    );
                }
                (b"min interval", v) => {
                    min_interval = Some(u32::decode_bencode_object(v).context("min interval")?);
                }
                (b"tracker id", v) => {
                    tracker_id = Some(Bytes::from(
                        v.try_into_bytes().context("tracker id")?.to_vec(),
                    ));
                }
                (b"complete", v) => {
                    complete = Some(u32::decode_bencode_object(v).context("complete")?);
                }
                (b"incomplete", v) => {
                    incomplete = Some(u32::decode_bencode_object(v).context("incomplete")?);
                }
                _ => (),
            }
        }
        let interval = interval.ok_or_else(|| BendyError::missing_field("interval"))?;
        Ok(HttpAnnounceResponse::Success(AnnounceResponse {
            interval,
            peers,
            warning_message,
            min_interval,
            tracker_id,
            complete,
            incomplete,
            leechers: None,
            seeders: None,
        }))
    }
}

#[derive(Debug, Error)]
pub(crate) enum HttpTrackerError {
    #[error("failed to build HTTP client")]
    BuildClient(#[source] reqwest::Error),
    #[error("failed to send request to HTTP tracker")]
    SendRequest(#[source] reqwest::Error),
    #[error("HTTP tracker responded with HTTP error")]
    HttpStatus(#[source] reqwest::Error),
    #[error("failed to read HTTP tracker response")]
    ReadBody(#[source] reqwest::Error),
    #[error("failed to parse HTTP tracker response")]
    ParseResponse(#[source] UnbencodeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use std::net::SocketAddr;

    #[test]
    fn test_decode_response() {
        let mut buf = BytesMut::new();
        buf.put(b"d8:completei47e10:incompletei5e8:intervali1800e12:min inter".as_slice());
        buf.put(b"vali1800e5:peers300:w\x94bls\xdf\xd8\xb4C,\x1a\xe1\xba\x16".as_slice());
        buf.put(b"\xdf\xe8\x0f0\xc1(\r\xab\xc8\xd5\xb32\xe9\xec\x86~\xd4UX]A".as_slice());
        buf.put(b"\xf1-\x0e\xc30\xd6\xa1g\xd9\xe8z\xcbv\xbfe\xaen\xdc\xb41%/G".as_slice());
        buf.put(b"\xa1\xa7N\xc5i\x88A\xf1Bs\x93\xd1\x00\x01\x9a\x1d\x83\xb6".as_slice());
        buf.put(b"\xc8\xd5\xbc\xd18-N\\-[\x17\x85\xc8\xd5\xb9U\x96>ZIH\x15".as_slice());
        buf.put(b"\x11\x05\xebT\xc2%`S\x83\xb0\\V\x90\x04SY\xb3\xec\xac\x06".as_slice());
        buf.put(b"\xaa[Wns\x08.\xc9\xc8o\xe0\xf5\x94\xe8R\xaa\xe86\x1a\xe1".as_slice());
        buf.put(b"\x1b!nb\xc4\x85Mn\x83*\xa15\x17\x13\x8dp\xb3\xe9\xc1(\r\xa2".as_slice());
        buf.put(b"\xb3\x8c\xc3\xf6xC-\x15\xb9\x95Z\t\xc7I-\x0c\xdct\xc8\xd5E".as_slice());
        buf.put(b"\xaaM\xe3\x10\x9f\xd5\xf5\xb3;z\xed\xd9\x8a\xd5\x1d\xa1\x0b".as_slice());
        buf.put(b"\xd4f9K!\x9b\xb9\x99\xb3\x1b\xe6'gW\xd6\xdeu\xcfeXO\xc1\xc8".as_slice());
        buf.put(b"-\xd4:x<.\xa6\x18%a\x1a\xc8\xd5\xc1 \x7f\x98\xc8\xd5\xd9".as_slice());
        buf.put(b"\x8a\xc2^\xe0\x02m\xc9\x98\xa6\x00\x01\xb9\xba\xf9\t\x1a".as_slice());
        buf.put(b"\xe1\x86\x13\xbc[\xce\x9bD\xeb,G\xd9|.5\xfd\xf1\xd4\xf1\x1b".as_slice());
        buf.put(b"\"\x14I\xa4\xbe\xb0)\x1b\xedp\xcb\xac\xf1\xe0.I\x84m\xc9".as_slice());
        buf.put(b"\x98\xaf\x00\x01e".as_slice());
        let res = decode_bencode::<HttpAnnounceResponse>(&buf).unwrap();
        let HttpAnnounceResponse::Success(announcement) = res else {
            panic!("Announcement failed");
        };
        assert_eq!(
            announcement,
            AnnounceResponse {
                interval: 1800,
                peers: vec![
                    "119.148.98.108:29663".parse::<Peer>().unwrap(),
                    "216.180.67.44:6881".parse::<Peer>().unwrap(),
                    "186.22.223.232:3888".parse::<Peer>().unwrap(),
                    "193.40.13.171:51413".parse::<Peer>().unwrap(),
                    "179.50.233.236:34430".parse::<Peer>().unwrap(),
                    "212.85.88.93:16881".parse::<Peer>().unwrap(),
                    "45.14.195.48:54945".parse::<Peer>().unwrap(),
                    "103.217.232.122:52086".parse::<Peer>().unwrap(),
                    "191.101.174.110:56500".parse::<Peer>().unwrap(),
                    "49.37.47.71:41383".parse::<Peer>().unwrap(),
                    "78.197.105.136:16881".parse::<Peer>().unwrap(),
                    "66.115.147.209:1".parse::<Peer>().unwrap(),
                    "154.29.131.182:51413".parse::<Peer>().unwrap(),
                    "188.209.56.45:20060".parse::<Peer>().unwrap(),
                    "45.91.23.133:51413".parse::<Peer>().unwrap(),
                    "185.85.150.62:23113".parse::<Peer>().unwrap(),
                    "72.21.17.5:60244".parse::<Peer>().unwrap(),
                    "194.37.96.83:33712".parse::<Peer>().unwrap(),
                    "92.86.144.4:21337".parse::<Peer>().unwrap(),
                    "179.236.172.6:43611".parse::<Peer>().unwrap(),
                    "87.110.115.8:11977".parse::<Peer>().unwrap(),
                    "200.111.224.245:38120".parse::<Peer>().unwrap(),
                    "82.170.232.54:6881".parse::<Peer>().unwrap(),
                    "27.33.110.98:50309".parse::<Peer>().unwrap(),
                    "77.110.131.42:41269".parse::<Peer>().unwrap(),
                    "23.19.141.112:46057".parse::<Peer>().unwrap(),
                    "193.40.13.162:45964".parse::<Peer>().unwrap(),
                    "195.246.120.67:11541".parse::<Peer>().unwrap(),
                    "185.149.90.9:51017".parse::<Peer>().unwrap(),
                    "45.12.220.116:51413".parse::<Peer>().unwrap(),
                    "69.170.77.227:4255".parse::<Peer>().unwrap(),
                    "213.245.179.59:31469".parse::<Peer>().unwrap(),
                    "217.138.213.29:41227".parse::<Peer>().unwrap(),
                    "212.102.57.75:8603".parse::<Peer>().unwrap(),
                    "185.153.179.27:58919".parse::<Peer>().unwrap(),
                    "103.87.214.222:30159".parse::<Peer>().unwrap(),
                    "101.88.79.193:51245".parse::<Peer>().unwrap(),
                    "212.58.120.60:11942".parse::<Peer>().unwrap(),
                    "24.37.97.26:51413".parse::<Peer>().unwrap(),
                    "193.32.127.152:51413".parse::<Peer>().unwrap(),
                    "217.138.194.94:57346".parse::<Peer>().unwrap(),
                    "109.201.152.166:1".parse::<Peer>().unwrap(),
                    "185.186.249.9:6881".parse::<Peer>().unwrap(),
                    "134.19.188.91:52891".parse::<Peer>().unwrap(),
                    "68.235.44.71:55676".parse::<Peer>().unwrap(),
                    "46.53.253.241:54513".parse::<Peer>().unwrap(),
                    "27.34.20.73:42174".parse::<Peer>().unwrap(),
                    "176.41.27.237:28875".parse::<Peer>().unwrap(),
                    "172.241.224.46:18820".parse::<Peer>().unwrap(),
                    "109.201.152.175:1".parse::<Peer>().unwrap(),
                ],
                warning_message: None,
                min_interval: Some(1800),
                tracker_id: None,
                complete: Some(47),
                incomplete: Some(5),
                leechers: None,
                seeders: None,
            }
        );
    }

    #[test]
    fn test_decode_response_with_peers6() {
        let res = decode_bencode::<HttpAnnounceResponse>(
            b"d8:intervali1800e5:peers6:iiiipp6:peers618:iiiiiiiiiiiiiiiippe",
        )
        .unwrap();
        let HttpAnnounceResponse::Success(announcement) = res else {
            panic!("Announcement failed");
        };
        assert_eq!(
            announcement,
            AnnounceResponse {
                interval: 1800,
                peers: vec![
                    "105.105.105.105:28784".parse::<Peer>().unwrap(),
                    "[6969:6969:6969:6969:6969:6969:6969:6969]:28784"
                        .parse::<Peer>()
                        .unwrap(),
                ],
                warning_message: None,
                min_interval: None,
                tracker_id: None,
                complete: None,
                incomplete: None,
                leechers: None,
                seeders: None,
            }
        );
    }

    #[test]
    fn test_decode_response_bad_peers6() {
        let e = decode_bencode::<HttpAnnounceResponse>(
            b"d8:completei45e10:downloadedi8384e10:incompletei4e8:intervali900e12:min intervali300e6:peers66:\x00\x00\x00\x00\x00\x0010:tracker id7:AniRenae"
        ).unwrap_err();
        let UnbencodeError::Bendy(e) = e else {
            panic!("Error was not raised within FromBencode");
        };
        assert_eq!(
            e.to_string(),
            "Error: malformed content discovered: unexpected end of packet in peers6"
        );
    }

    #[test]
    fn test_decode_failure_response() {
        let res = decode_bencode::<HttpAnnounceResponse>(b"d14:failure reason14:too much stuffe")
            .unwrap();
        assert_eq!(res, HttpAnnounceResponse::Failure("too much stuff".into()));
    }

    #[test]
    fn test_decode_noncompact_response() {
        let res = decode_bencode::<HttpAnnounceResponse>(
            b"d8:completei431e10:incompletei14e8:intervali1800e5:peersld2:ip22:2001:41d0:1004:20b5::17:peer id20:-TR3000-23xhfykztwo84:porti51413eed2:ip18:2001:41d0:e:907::17:peer id20:-lt0D80-\xf8\x01\x92N+!{\x06\xcc\x15\xf0\xc44:porti12179eed2:ip14:185.125.190.597:peer id20:T03I--00N4b1YqQdAWh44:porti6892eed2:ip19:2403:5812:a03e::2227:peer id20:-TR3000-83e2ltycmh6c4:porti51413eed2:ip37:2003:f1:6f0f:dd00:c0ab:7cff:febd:274a7:peer id20:-TR3000-9e0zt0knchh44:porti51413eeee"
        ).unwrap();
        let HttpAnnounceResponse::Success(announcement) = res else {
            panic!("Announcement failed");
        };
        assert_eq!(
            announcement,
            AnnounceResponse {
                interval: 1800,
                peers: vec![
                    Peer {
                        address: "[2001:41d0:1004:20b5::1]:51413"
                            .parse::<SocketAddr>()
                            .unwrap(),
                        id: Some(PeerId::from(b"-TR3000-23xhfykztwo8")),
                    },
                    Peer {
                        address: "[2001:41d0:e:907::1]:12179".parse::<SocketAddr>().unwrap(),
                        id: Some(PeerId::from(
                            b"-lt0D80-\xf8\x01\x92N+!{\x06\xcc\x15\xf0\xc4"
                        )),
                    },
                    Peer {
                        address: "185.125.190.59:6892".parse::<SocketAddr>().unwrap(),
                        id: Some(PeerId::from(b"T03I--00N4b1YqQdAWh4")),
                    },
                    Peer {
                        address: "[2403:5812:a03e::222]:51413".parse::<SocketAddr>().unwrap(),
                        id: Some(PeerId::from(b"-TR3000-83e2ltycmh6c")),
                    },
                    Peer {
                        address: "[2003:f1:6f0f:dd00:c0ab:7cff:febd:274a]:51413"
                            .parse::<SocketAddr>()
                            .unwrap(),
                        id: Some(PeerId::from(b"-TR3000-9e0zt0knchh4")),
                    },
                ],
                warning_message: None,
                min_interval: None,
                tracker_id: None,
                complete: Some(431),
                incomplete: Some(14),
                leechers: None,
                seeders: None,
            }
        );
    }

    #[test]
    fn test_decode_noncompact_response_no_peer_id() {
        let res = decode_bencode::<HttpAnnounceResponse>(
            b"d8:intervali900e5:peersld2:ip13:62.11.247.2494:porti8012eed2:ip13:185.148.1.1584:porti24810eed2:ip14:108.51.168.1554:porti51413eed2:ip14:207.179.235.144:porti49192eeee"
        ).unwrap();
        let HttpAnnounceResponse::Success(announcement) = res else {
            panic!("Announcement failed");
        };
        assert_eq!(
            announcement,
            AnnounceResponse {
                interval: 900,
                peers: vec![
                    "62.11.247.249:8012".parse::<Peer>().unwrap(),
                    "185.148.1.158:24810".parse::<Peer>().unwrap(),
                    "108.51.168.155:51413".parse::<Peer>().unwrap(),
                    "207.179.235.14:49192".parse::<Peer>().unwrap(),
                ],
                warning_message: None,
                min_interval: None,
                tracker_id: None,
                complete: None,
                incomplete: None,
                leechers: None,
                seeders: None,
            }
        );
    }
}
