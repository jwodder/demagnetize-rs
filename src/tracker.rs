pub(crate) mod http;
pub(crate) mod udp;
use self::http::*;
use self::udp::*;
use crate::consts::{LEFT, NUMWANT, TRACKER_STOP_TIMEOUT, TRACKER_TIMEOUT};
use crate::peer::Peer;
use crate::types::{InfoHash, Key, LocalPeer, PeerId};
use crate::util::{comma_list, ErrorChain, PacketError};
use bytes::Bytes;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Tracker {
    Http(HttpTracker),
    Udp(UdpTracker),
}

impl Tracker {
    pub(crate) fn url_str(&self) -> &str {
        match self {
            Tracker::Http(tr) => tr.url_str(),
            Tracker::Udp(tr) => tr.url_str(),
        }
    }

    pub(crate) async fn get_peers(
        &self,
        info_hash: &InfoHash,
        local: &LocalPeer,
        sender: Sender<Peer>,
    ) -> Result<(), TrackerError> {
        log::info!("Requesting peers for {info_hash} from {self}");
        timeout(TRACKER_TIMEOUT, self._get_peers(info_hash, local, sender))
            .await
            .unwrap_or(Err(TrackerError::Timeout))
    }

    async fn connect<'a>(
        &'a self,
        info_hash: &'a InfoHash,
        local: &'a LocalPeer,
    ) -> Result<TrackerSession<'a>, TrackerError> {
        let inner = match self {
            Tracker::Http(t) => InnerTrackerSession::Http(t.connect().await?),
            Tracker::Udp(t) => InnerTrackerSession::Udp(t.connect().await?),
        };
        Ok(TrackerSession {
            inner,
            info_hash,
            local,
        })
    }

    async fn _get_peers(
        &self,
        info_hash: &InfoHash,
        local: &LocalPeer,
        sender: Sender<Peer>,
    ) -> Result<(), TrackerError> {
        let s = self.connect(info_hash, local).await?;
        let peers = s.start().await?.peers;
        log::info!("{self} returned {} peers", peers.len());
        log::debug!("{self} returned peers: {}", comma_list(&peers));
        tokio::join!(
            async move {
                for p in peers {
                    if sender.send(p).await.is_err() {
                        break;
                    }
                }
            },
            async move {
                match timeout(TRACKER_STOP_TIMEOUT, s.stop()).await {
                    Ok(Ok(_)) => (),
                    Ok(Err(e)) => log::warn!("failure sending \"stopped\" announcement to {self} for {info_hash}: {}", ErrorChain(e)),
                    Err(_) => log::warn!("{self} did not response to \"stopped\" announcement for {info_hash} in time"),
                }
            }
        );
        Ok(())
    }
}

impl fmt::Display for Tracker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Tracker::Http(http) => write!(f, "{http}"),
            Tracker::Udp(udp) => write!(f, "{udp}"),
        }
    }
}

impl FromStr for Tracker {
    type Err = TrackerUrlError;

    fn from_str(s: &str) -> Result<Tracker, TrackerUrlError> {
        let url = Url::parse(s)?;
        match url.scheme() {
            "http" | "https" => Ok(Tracker::Http(HttpTracker::try_from(url)?)),
            "udp" => Ok(Tracker::Udp(UdpTracker::try_from(url)?)),
            sch => Err(TrackerUrlError::UnsupportedScheme(sch.into())),
        }
    }
}

struct TrackerSession<'a> {
    inner: InnerTrackerSession<'a>,
    info_hash: &'a InfoHash,
    local: &'a LocalPeer,
}

enum InnerTrackerSession<'a> {
    Http(HttpTrackerSession<'a>),
    Udp(UdpTrackerSession<'a>),
}

impl<'a> TrackerSession<'a> {
    fn tracker_display(&self) -> String {
        match &self.inner {
            InnerTrackerSession::Http(s) => s.tracker.to_string(),
            InnerTrackerSession::Udp(s) => s.tracker.to_string(),
        }
    }

    async fn start(&self) -> Result<AnnounceResponse, TrackerError> {
        log::trace!(
            "Sending 'started' announcement to {} for {}",
            self.tracker_display(),
            self.info_hash
        );
        self.announce(Announcement {
            info_hash: self.info_hash,
            peer_id: &self.local.id,
            downloaded: 0,
            left: LEFT,
            uploaded: 0,
            event: AnnounceEvent::Started,
            key: self.local.key,
            numwant: NUMWANT,
            port: self.local.port,
        })
        .await
    }

    async fn stop(&self) -> Result<AnnounceResponse, TrackerError> {
        log::trace!(
            "Sending 'stopped' announcement to {} for {}",
            self.tracker_display(),
            self.info_hash
        );
        self.announce(Announcement {
            info_hash: self.info_hash,
            peer_id: &self.local.id,
            downloaded: 0,
            left: LEFT,
            uploaded: 0,
            event: AnnounceEvent::Stopped,
            key: self.local.key,
            numwant: NUMWANT,
            port: self.local.port,
        })
        .await
    }

    async fn announce<'b>(
        &self,
        announcement: Announcement<'b>,
    ) -> Result<AnnounceResponse, TrackerError> {
        let announcement = match &self.inner {
            InnerTrackerSession::Http(s) => s.announce(announcement).await?,
            InnerTrackerSession::Udp(s) => s.announce(announcement).await?,
        };
        if let Some(msg) = announcement.warning_message.as_ref() {
            log::trace!(
                "{} replied with warning in response to {} announcement: {:?}",
                self.tracker_display(),
                self.info_hash,
                msg,
            );
        }
        Ok(announcement)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum TrackerUrlError {
    #[error("invalid tracker URL")]
    Url(#[from] url::ParseError),
    #[error("unsupported tracker URL scheme: {0:?}")]
    UnsupportedScheme(String),
    #[error("no host in tracker URL")]
    NoHost,
    #[error("no port in UDP tracker URL")]
    NoUdpPort,
}

#[derive(Debug, Error)]
pub(crate) enum TrackerError {
    #[error("interactions with tracker did not complete in time")]
    Timeout,
    #[error("tracker replied with error message {0:?}")]
    Failure(String),
    #[error(transparent)]
    Http(#[from] HttpTrackerError),
    #[error(transparent)]
    Udp(#[from] UdpError),
    #[error("UDP tracker sent response with invalid length")]
    UdpPacketLen(#[from] PacketError),
    #[error("UDP tracker sent response with unexpected or unsupported action; expected {expected}, got {got}")]
    BadUdpAction { expected: u32, got: u32 },
    #[error("response from UDP tracker did not contain expected transaction ID; expected {expected:#x}, got {got:#x}")]
    XactionMismatch { expected: u32, got: u32 },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum AnnounceEvent {
    Announce,
    Completed,
    Started,
    Stopped,
}

impl AnnounceEvent {
    fn add_query_param(&self, url: &mut Url) {
        let value = match self {
            AnnounceEvent::Announce => return,
            AnnounceEvent::Completed => "completed",
            AnnounceEvent::Started => "started",
            AnnounceEvent::Stopped => "stopped",
        };
        url.query_pairs_mut().append_pair("event", value);
    }

    fn for_udp(&self) -> u32 {
        match self {
            AnnounceEvent::Announce => 0,
            AnnounceEvent::Completed => 1,
            AnnounceEvent::Started => 2,
            AnnounceEvent::Stopped => 3,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Announcement<'a> {
    info_hash: &'a InfoHash,
    peer_id: &'a PeerId,
    downloaded: u64,
    left: u64,
    uploaded: u64,
    event: AnnounceEvent,
    key: Key,
    numwant: u32,
    port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AnnounceResponse {
    interval: u32,
    peers: Vec<Peer>,
    warning_message: Option<String>,
    min_interval: Option<u32>,
    tracker_id: Option<Bytes>,
    complete: Option<u32>,
    incomplete: Option<u32>,
    leechers: Option<u32>,
    seeders: Option<u32>,
}
