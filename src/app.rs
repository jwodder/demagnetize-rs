use crate::config::Config;
use crate::consts::PEER_ID_PREFIX;
use crate::tracker::TrackerCrypto;
use crate::types::{Key, PeerId};
use rand::Rng;
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct App {
    pub(crate) cfg: Config,
    pub(crate) local: LocalPeer,
    pub(crate) tracker_crypto: Option<TrackerCrypto>,
}

impl App {
    pub(crate) fn new<R: Rng>(cfg: Config, mut rng: R) -> App {
        let id = PeerId::generate(PEER_ID_PREFIX, &mut rng);
        let key = rng.random::<Key>();
        let port = cfg.trackers.local_port.generate(&mut rng);
        let local = LocalPeer { id, key, port };
        App {
            cfg,
            local,
            tracker_crypto: None,
        }
    }

    pub(crate) fn get_tracker_crypto(&self) -> TrackerCrypto {
        self.tracker_crypto.unwrap_or_default()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalPeer {
    pub(crate) id: PeerId,
    pub(crate) key: Key,
    pub(crate) port: u16,
}

impl fmt::Display for LocalPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "id = {}, key = {}, port = {}",
            self.id, self.key, self.port
        )
    }
}
