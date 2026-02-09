use crate::asyncutil::ShutdownGroup;
use crate::config::Config;
use crate::consts::PEER_ID_PREFIX;
use crate::dht::{CreateDhtActorError, DhtActor, DhtHandle, DhtHandleError, FoundPeers};
use crate::peer::CryptoMode;
use crate::types::{InfoHash, Key, PeerId};
use rand::{RngExt, rngs::StdRng};
use std::fmt;
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug)]
pub(crate) struct App {
    pub(crate) cfg: Config,
    pub(crate) local: LocalPeer,
    pub(crate) shutdown_group: ShutdownGroup,
    dht_handle: Mutex<Option<DhtHandle>>,
}

impl App {
    pub(crate) fn new<R: RngExt>(cfg: Config, mut rng: R) -> App {
        let id = PeerId::generate(PEER_ID_PREFIX, &mut rng);
        let key = rng.random::<Key>();
        let port = cfg.trackers.local_port.generate(&mut rng);
        let local = LocalPeer { id, key, port };
        App {
            cfg,
            local,
            shutdown_group: ShutdownGroup::new(),
            dht_handle: Mutex::new(None),
        }
    }

    pub(crate) fn get_crypto_mode(&self, requires_crypto: bool) -> Option<CryptoMode> {
        self.cfg.general.encrypt.get_crypto_mode(requires_crypto)
    }

    async fn get_dht_handle(&self) -> Result<DhtHandle, CreateDhtActorError> {
        let mut guard = self.dht_handle.lock().await;
        if let Some(handle) = guard.as_ref() {
            Ok(handle.clone())
        } else {
            let rng = rand::make_rng::<StdRng>();
            let timeout = self.cfg.dht.query_timeout;
            let bootstrap_nodes = self.cfg.dht.bootstrap_nodes.as_vec().clone();
            let (actor, handle) = DhtActor::new(rng, timeout, bootstrap_nodes).await?;
            tokio::spawn(actor.run());
            *guard = Some(handle.clone());
            Ok(handle)
        }
    }

    pub(crate) async fn get_peers_from_dht(
        &self,
        info_hash: InfoHash,
    ) -> Result<FoundPeers, DhtError> {
        let handle = self.get_dht_handle().await?;
        handle.lookup_peers(info_hash).await.map_err(Into::into)
    }

    pub(crate) async fn shutdown(&self) {
        {
            let guard = self.dht_handle.lock().await;
            if let Some(handle) = guard.as_ref() {
                handle.shutdown().await;
            }
        }
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

#[derive(Debug, Error)]
pub(crate) enum DhtError {
    #[error("failed to create DHT node actor")]
    Create(#[from] CreateDhtActorError),
    #[error(transparent)]
    Handle(#[from] DhtHandleError),
}
