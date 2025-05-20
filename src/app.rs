use crate::config::{Config, CryptoPreference};
use crate::consts::PEER_ID_PREFIX;
use crate::peer::CryptoMode;
use crate::types::{Key, PeerId};
use rand::Rng;
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct App {
    pub(crate) cfg: Config,
    pub(crate) local: LocalPeer,
}

impl App {
    pub(crate) fn new<R: Rng>(cfg: Config, mut rng: R) -> App {
        let id = PeerId::generate(PEER_ID_PREFIX, &mut rng);
        let key = rng.random::<Key>();
        let port = cfg.trackers.local_port.generate(&mut rng);
        let local = LocalPeer { id, key, port };
        App { cfg, local }
    }

    pub(crate) fn get_crypto_mode(&self, requires_crypto: bool) -> Option<CryptoMode> {
        match (self.cfg.general.encrypt, requires_crypto) {
            (CryptoPreference::Always, _) => Some(CryptoMode::Encrypt),
            (CryptoPreference::Prefer, true) => Some(CryptoMode::Encrypt),
            (CryptoPreference::Prefer, false) => Some(CryptoMode::Prefer),
            (CryptoPreference::IfRequired, true) => Some(CryptoMode::Encrypt),
            (CryptoPreference::IfRequired, false) => Some(CryptoMode::Plain),
            (CryptoPreference::Never, true) => None,
            (CryptoPreference::Never, false) => Some(CryptoMode::Plain),
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
