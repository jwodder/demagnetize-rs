pub(crate) mod http;
pub(crate) mod udp;
use self::http::*;
use self::udp::*;
use crate::app::App;
use crate::consts::LEFT;
use crate::peer::Peer;
use crate::types::{InfoHash, Key, PeerId};
use crate::util::{comma_list, ErrorChain};
use bytes::Bytes;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tokio::time::timeout;
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Tracker {
    Http(HttpTracker),
    Udp(UdpTracker),
}

impl Tracker {
    pub(crate) fn url_string(&self) -> String {
        match self {
            Tracker::Http(tr) => tr.url_string(),
            Tracker::Udp(tr) => tr.url_string(),
        }
    }

    pub(crate) fn peer_getter(&self, info_hash: InfoHash, app: Arc<App>) -> PeerGetter<'_> {
        PeerGetter {
            tracker: self,
            info_hash,
            app,
            tracker_crypto: None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PeerGetter<'a> {
    tracker: &'a Tracker,
    info_hash: InfoHash,
    app: Arc<App>,
    tracker_crypto: Option<TrackerCrypto>,
}

impl PeerGetter<'_> {
    pub(crate) fn tracker_crypto(mut self, tc: Option<TrackerCrypto>) -> Self {
        self.tracker_crypto = tc;
        self
    }

    pub(crate) async fn run(self) -> Result<Vec<Peer>, TrackerError> {
        log::info!(
            "Requesting peers for {} from {}",
            self.info_hash,
            self.tracker
        );
        timeout(
            self.app.cfg.trackers.announce_timeout,
            self.inner_get_peers(),
        )
        .await
        .unwrap_or(Err(TrackerError::Timeout))
    }

    async fn inner_get_peers(self) -> Result<Vec<Peer>, TrackerError> {
        let mut s = self.connect().await?;
        let peers = s.start().await?.peers;
        let display = self.tracker.to_string();
        let info_hash = self.info_hash;
        log::info!("{display} returned {} peers for {info_hash}", peers.len());
        log::debug!(
            "{display} returned peers for {info_hash}: {}",
            comma_list(&peers)
        );
        self.app.shutdown_group.spawn(|token| async move {
            tokio::select! {
                () = token.cancelled() => log::trace!(r#""stopped" announcement to {display} for {info_hash} cancelled"#),
                r = s.stop() => {
                    if let Err(e) = r {
                        log::warn!(
                            r#"failure sending "stopped" announcement to {display} for {info_hash}: {}"#,
                            ErrorChain(e)
                        );
                    }
                }
            }
        });
        Ok(peers)
    }

    async fn connect(&self) -> Result<TrackerSession, TrackerError> {
        let inner = match self.tracker {
            Tracker::Http(t) => InnerTrackerSession::Http(t.connect()?),
            Tracker::Udp(t) => InnerTrackerSession::Udp(t.connect().await?),
        };
        Ok(TrackerSession {
            inner,
            info_hash: self.info_hash,
            app: Arc::clone(&self.app),
            tracker_crypto: self.tracker_crypto,
        })
    }
}

impl fmt::Display for Tracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

struct TrackerSession {
    inner: InnerTrackerSession,
    info_hash: InfoHash,
    app: Arc<App>,
    tracker_crypto: Option<TrackerCrypto>,
}

enum InnerTrackerSession {
    Http(HttpTrackerSession),
    Udp(UdpTrackerSession),
}

impl TrackerSession {
    fn get_tracker_crypto(&self) -> TrackerCrypto {
        self.tracker_crypto
            .unwrap_or_else(|| self.app.cfg.general.encrypt.get_tracker_crypto())
    }

    fn tracker_display(&self) -> String {
        match &self.inner {
            InnerTrackerSession::Http(s) => s.tracker.to_string(),
            InnerTrackerSession::Udp(s) => s.tracker.to_string(),
        }
    }

    async fn start(&mut self) -> Result<AnnounceResponse, TrackerError> {
        log::trace!(
            r#"Sending "started" announcement to {} for {}"#,
            self.tracker_display(),
            self.info_hash
        );
        self.announce(Announcement {
            info_hash: self.info_hash,
            peer_id: self.app.local.id,
            downloaded: 0,
            left: LEFT,
            uploaded: 0,
            event: AnnounceEvent::Started,
            key: self.app.local.key,
            numwant: self.app.cfg.trackers.numwant.get(),
            port: self.app.local.port,
            crypto: self.get_tracker_crypto(),
        })
        .await
    }

    async fn stop(&mut self) -> Result<AnnounceResponse, TrackerError> {
        log::trace!(
            r#"Sending "stopped" announcement to {} for {}"#,
            self.tracker_display(),
            self.info_hash
        );
        self.announce(Announcement {
            info_hash: self.info_hash,
            peer_id: self.app.local.id,
            downloaded: 0,
            left: LEFT,
            uploaded: 0,
            event: AnnounceEvent::Stopped,
            key: self.app.local.key,
            numwant: self.app.cfg.trackers.numwant.get(),
            port: self.app.local.port,
            crypto: self.get_tracker_crypto(),
        })
        .await
    }

    async fn announce(
        &mut self,
        announcement: Announcement,
    ) -> Result<AnnounceResponse, TrackerError> {
        let announcement = match &mut self.inner {
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
    Udp(#[from] UdpTrackerError),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum AnnounceEvent {
    #[allow(dead_code)]
    Announce,
    #[allow(dead_code)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct Announcement {
    info_hash: InfoHash,
    peer_id: PeerId,
    downloaded: u64,
    left: u64,
    uploaded: u64,
    event: AnnounceEvent,
    key: Key,
    numwant: u32,
    port: u16,
    crypto: TrackerCrypto,
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

/// Possible levels of encryption support to include in tracker announcements;
/// only used by HTTP trackers
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum TrackerCrypto {
    Required,
    #[default]
    Supported,
    Plain,
}

impl TrackerCrypto {
    fn add_query_param(&self, url: &mut Url) {
        match self {
            TrackerCrypto::Required => {
                url.query_pairs_mut().append_pair("requirecrypto", "1");
            }
            TrackerCrypto::Supported => {
                url.query_pairs_mut().append_pair("supportcrypto", "1");
            }
            TrackerCrypto::Plain => (),
        }
    }
}
