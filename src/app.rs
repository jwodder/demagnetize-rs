use crate::asyncutil::ShutdownGroup;
use crate::config::Config;
use crate::consts::PEER_ID_PREFIX;
use crate::peer::CryptoMode;
use crate::types::{Key, PeerId};
use rand::Rng;
use std::fmt;

#[derive(Debug)]
pub(crate) struct App {
    pub(crate) cfg: Config,
    pub(crate) local: LocalPeer,
    pub(crate) shutdown_group: ShutdownGroup,
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
            shutdown_group: ShutdownGroup::new(),
        }
    }

    pub(crate) fn get_crypto_mode(&self, requires_crypto: bool) -> Option<CryptoMode> {
        self.cfg.general.encrypt.get_crypto_mode(requires_crypto)
    }

    pub(crate) async fn shutdown(&self) {
        self.shutdown_group
            .shutdown(self.cfg.trackers.shutdown_timeout)
            .await;
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
