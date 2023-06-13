pub(crate) mod http;
mod packets;
pub(crate) mod udp;
use self::http::*;
use self::packets::*;
use self::udp::*;
use crate::consts::{LEFT, NUMWANT, TRACKER_STOP_TIMEOUT, TRACKER_TIMEOUT};
use crate::peer::Peer;
use crate::types::{InfoHash, LocalPeer};
use crate::util::comma_list;
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
        log::trace!("Sending 'started' announcement to {self} for {info_hash}");
        let peers = s.start().await?.into_peers();
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
                    // TODO: Display source errors for `e`:
                    Ok(Err(e)) => log::warn!("failure sending \"stopped\" announcement to {self} for {info_hash}: {e}"),
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
    async fn start(&self) -> Result<AnnounceResponse, TrackerError> {
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
        match &self.inner {
            InnerTrackerSession::Http(s) => s.announce(announcement).await,
            InnerTrackerSession::Udp(s) => s.announce(announcement).await,
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
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

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum TrackerError {
    #[error("interactions with tracker did not complete in time")]
    Timeout,
    #[error("tracker replied with error: {0}")]
    FailureResponse(String),
    // ???
}
