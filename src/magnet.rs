use crate::app::App;
use crate::asyncutil::{UniqueByExt, WorkerNursery};
use crate::torrent::{PathTemplate, TorrentFile};
use crate::tracker::{Tracker, TrackerUrlError};
use crate::types::{InfoHash, InfoHashError};
use crate::util::ErrorChain;
use futures_util::stream::{iter, StreamExt};
use patharg::InputArg;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Magnet {
    info_hash: InfoHash,
    display_name: Option<String>,
    trackers: Vec<Arc<Tracker>>,
}

impl Magnet {
    fn info_hash(&self) -> InfoHash {
        self.info_hash
    }

    fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    fn trackers(&self) -> &[Arc<Tracker>] {
        &self.trackers
    }

    pub(crate) async fn get_torrent_file(
        &self,
        app: Arc<App>,
    ) -> Result<TorrentFile, GetInfoError> {
        log::info!("Fetching metadata info for {self}");
        let info_hash = self.info_hash();
        let (tracker_nursery, peer_stream) = WorkerNursery::new(app.cfg.trackers.jobs_per_magnet);
        for tracker in self.trackers() {
            let tracker = Arc::clone(tracker);
            let app = Arc::clone(&app);
            let display = self.to_string();
            tracker_nursery
                .spawn(async move {
                    match tracker.peer_getter(info_hash, app).run().await {
                        Ok(peers) => iter(peers),
                        Err(e) => {
                            log::warn!(
                                "Error communicating with {} for {}: {}",
                                tracker,
                                display,
                                ErrorChain(e)
                            );
                            iter(Vec::new())
                        }
                    }
                })
                .expect("tracker nursery should not be closed");
        }
        drop(tracker_nursery);
        // Weed out duplicate peers, ignoring differences in peer IDs and
        // requires_crypto fields … for now:
        let mut peer_stream = peer_stream.flatten().unique_by(|peer| peer.address);
        let (peer_tasks, mut receiver) = WorkerNursery::new(app.cfg.peers.jobs_per_magnet);
        let peer_job = tokio::spawn(async move {
            while let Some(peer) = peer_stream.next().await {
                peer_tasks
                    .spawn({
                        let app = Arc::clone(&app);
                        async move {
                            let r = peer.info_getter(info_hash, app).run().await;
                            (peer, r)
                        }
                    })
                    .expect("peer task nursery should not be closed");
            }
            // peer_tasks is dropped here, allowing for closure.
        });
        while let Some((peer, r)) = receiver.next().await {
            match r {
                Ok(info) => {
                    let tf = TorrentFile::new(info, self.trackers.clone());
                    peer_job.abort();
                    return Ok(tf);
                }
                Err(e) => log::warn!(
                    "Failed to fetch info for {} from {}: {}",
                    self,
                    peer,
                    ErrorChain(e)
                ),
            }
        }
        Err(GetInfoError)
    }

    pub(crate) async fn download_torrent_file(
        &self,
        template: Arc<PathTemplate>,
        app: Arc<App>,
    ) -> Result<(), DownloadInfoError> {
        let tf = self.get_torrent_file(app).await?;
        tf.save(&template).await?;
        Ok(())
    }
}

impl FromStr for Magnet {
    type Err = MagnetError;

    fn from_str(s: &str) -> Result<Magnet, MagnetError> {
        let url = Url::parse(s)?;
        if url.scheme() != "magnet" {
            return Err(MagnetError::NotMagnet);
        }
        let mut info_hash = None;
        let mut dn = None;
        let mut trackers = Vec::new();
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "xt" => {
                    if info_hash.is_none() {
                        info_hash = Some(parse_xt(&v)?);
                    } else {
                        return Err(MagnetError::MultipleXt);
                    }
                }
                "dn" => {
                    let _ = dn.insert(v);
                }
                "tr" => trackers.push(Arc::new(v.parse::<Tracker>()?)),
                _ => (),
            }
        }
        let Some(info_hash) = info_hash else {
            return Err(MagnetError::NoXt);
        };
        if trackers.is_empty() {
            return Err(MagnetError::NoTrackers);
        }
        Ok(Magnet {
            info_hash,
            display_name: dn.map(String::from),
            trackers,
        })
    }
}

impl fmt::Display for Magnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(dn) = self.display_name() {
            write!(f, "{dn:?} ({})", self.info_hash)
        } else {
            write!(f, "{}", self.info_hash)
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum MagnetError {
    #[error("invalid URI")]
    Url(#[from] url::ParseError),
    #[error("not a magnet URI")]
    NotMagnet,
    #[error("magnet URI lacks \"xt\" parameter")]
    NoXt,
    #[error("invalid \"xt\" parameter")]
    InvalidXt(#[from] XtError),
    #[error("magnet URI has multiple \"xt\" parameters")]
    MultipleXt,
    #[error("no trackers given in magnet URI")]
    NoTrackers,
    #[error("invalid \"tr\" parameter")]
    InvalidTracker(#[from] TrackerUrlError),
}

fn parse_xt(xt: &str) -> Result<InfoHash, XtError> {
    let Some(s) = xt.strip_prefix("urn:") else {
        return Err(XtError::NotUrn);
    };
    let Some(s) = s.strip_prefix("btih:") else {
        return Err(XtError::NotBtih);
    };
    Ok(s.parse::<InfoHash>()?)
}

#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum XtError {
    #[error("\"xt\" parameter is not a URN")]
    NotUrn,
    #[error("\"xt\" parameter is not in the \"btih\" namespace")]
    NotBtih,
    #[error("\"xt\" parameter contains invalid info hash")]
    InfoHash(#[from] InfoHashError),
}

#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
#[error("no peer returned metadata info")]
pub(crate) struct GetInfoError;

#[derive(Debug, Error)]
pub(crate) enum DownloadInfoError {
    #[error(transparent)]
    Get(#[from] GetInfoError),
    #[error("failed to save torrent file")]
    Save(#[from] std::io::Error),
}

pub(crate) async fn parse_magnets_file(input: InputArg) -> Result<Vec<Magnet>, MagnetsFileError> {
    let mut lines = input
        .async_lines()
        .await
        .map_err(MagnetsFileError::Open)?
        .enumerate();
    let mut magnets = Vec::new();
    while let Some((i, r)) = lines.next().await {
        let ln = r.map_err(MagnetsFileError::Read)?;
        let ln = ln.trim();
        if ln.is_empty() || ln.starts_with('#') {
            continue;
        }
        match ln.parse::<Magnet>() {
            Ok(m) => magnets.push(m),
            Err(e) => {
                return Err(MagnetsFileError::Parse {
                    lineno: i + 1,
                    source: e,
                })
            }
        }
    }
    Ok(magnets)
}

#[derive(Debug, Error)]
pub(crate) enum MagnetsFileError {
    #[error("failed to open file")]
    Open(#[source] std::io::Error),
    #[error("failed reading from file")]
    Read(#[source] std::io::Error),
    #[error("invalid magnet link on line {lineno}")]
    Parse { lineno: usize, source: MagnetError },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_magnet() {
        let magnet = "magnet:?xt=urn:btih:28c55196f57753c40aceb6fb58617e6995a7eddb&dn=debian-11.2.0-amd64-netinst.iso&tr=http%3A%2F%2Fbttracker.debian.org%3A6969%2Fannounce".parse::<Magnet>().unwrap();
        assert_eq!(
            magnet.info_hash().as_bytes(),
            b"\x28\xC5\x51\x96\xF5\x77\x53\xC4\x0A\xCE\xB6\xFB\x58\x61\x7E\x69\x95\xA7\xED\xDB"
        );
        assert_eq!(
            magnet.display_name(),
            Some("debian-11.2.0-amd64-netinst.iso")
        );
        assert_eq!(
            magnet.trackers(),
            [Arc::new(
                "http://bttracker.debian.org:6969/announce"
                    .parse::<Tracker>()
                    .unwrap()
            )]
        );
    }
}
