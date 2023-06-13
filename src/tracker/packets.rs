use crate::peer::Peer;
use crate::types::{InfoHash, Key, PeerId};
use bytes::Bytes;

pub(super) enum AnnounceEvent {
    Announce,
    Completed,
    Started,
    Stopped,
}

pub(super) struct Announcement<'a> {
    pub(super) info_hash: &'a InfoHash,
    pub(super) peer_id: &'a PeerId,
    pub(super) downloaded: u64,
    pub(super) left: u64,
    pub(super) uploaded: u64,
    pub(super) event: AnnounceEvent,
    pub(super) key: Key,
    pub(super) numwant: u32,
    pub(super) port: u16,
}

pub(super) struct AnnounceResponse {
    pub(super) interval: u32,
    pub(super) peers: Option<Vec<Peer>>,
    pub(super) peers6: Option<Vec<Peer>>,
    pub(super) warning_message: Option<String>,
    pub(super) min_interval: Option<u32>,
    pub(super) tracker_id: Option<Bytes>,
    pub(super) complete: Option<u32>,
    pub(super) incomplete: Option<u32>,
    pub(super) leechers: Option<u32>,
    pub(super) seeders: Option<u32>,
}

impl AnnounceResponse {
    pub(super) fn into_peers(self) -> Vec<Peer> {
        let mut peers = Vec::new();
        if let Some(p) = self.peers {
            peers.extend(p);
        }
        if let Some(p) = self.peers6 {
            peers.extend(p);
        }
        peers
    }
}
