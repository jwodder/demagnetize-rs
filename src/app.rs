use crate::config::Config;
use crate::consts::PEER_ID_PREFIX;
use crate::peer::CryptoStrategy;
use crate::tracker::TrackerCrypto;
use crate::types::{Key, PeerId};
use rand::Rng;
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct App {
    pub(crate) cfg: Config,
    pub(crate) local: LocalPeer,
    pub(crate) tracker_crypto: Option<TrackerCrypto>,
    pub(crate) crypto_strategy: Option<CryptoStrategy>,
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
            crypto_strategy: None,
        }
    }

    pub(crate) fn get_tracker_crypto(&self) -> TrackerCrypto {
        self.tracker_crypto.unwrap_or_default()
    }

    pub(crate) fn get_crypto_strategy(&self, requires_crypto: bool) -> Option<CryptoStrategy> {
        match (self.crypto_strategy, requires_crypto) {
            (None, true) => Some(CryptoStrategy::Always),
            (None, false) => Some(CryptoStrategy::Fallback),
            (Some(CryptoStrategy::Fallback), true) => Some(CryptoStrategy::Always),
            (Some(CryptoStrategy::Never), true) => None,
            (Some(cs), _) => Some(cs),
        }
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
