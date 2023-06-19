use crate::peer::extensions::Extension;
use std::time::Duration;

/// Number of peers to request per tracker
pub(crate) const NUMWANT: u32 = 50;

/// Overall timeout for interacting with a tracker
pub(crate) const TRACKER_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for sending & receiving a "stopped" announcement to a tracker
pub(crate) const TRACKER_STOP_TIMEOUT: Duration = Duration::from_secs(3);

/// "left" value to use when announcing to a tracker for a torrent we have only
/// the magnet link of
pub(crate) const LEFT: u64 = 65535;

/// Prefix for generated peer IDs
pub(crate) static PEER_ID_PREFIX: &str = "-DM-0010-";

/// Size of buffer for receiving incoming UDP packets.  Any packets longer than
/// this are truncated.
pub(crate) const UDP_PACKET_LEN: usize = 65535;

/// Maximum metadata size to accept
pub(crate) const MAX_INFO_LENGTH: usize = 20 << 20; // 20 MiB

/// Timeout for connecting to a peer and performing the BitTorrent handshake
/// and extended handshake
pub(crate) const PEER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// BitTorrent protocol extensions supported by demagnetize
pub(crate) const SUPPORTED_EXTENSIONS: [Extension; 2] = [Extension::Bep10, Extension::Fast];

/// Extended message ID to declare for receiving BEP 9 messages
pub(crate) const UT_METADATA: u8 = 42;

/// Client string to send in extended handshakes and to use as the "Created by"
/// field in Torrent files
pub(crate) static CLIENT: &str = concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"));

/// Maximum length of a message to accept from a peer
pub(crate) const MAX_PEER_MSG_LEN: usize = 65535;

/// Maximum number of trackers per magnet link to communicate with at once
pub(crate) const TRACKERS_PER_MAGNET_LIMIT: usize = 30;

/// Maximum number of peers per magnet link to interact with at once
pub(crate) const PEERS_PER_MAGNET_LIMIT: usize = 30;

/// Maximum number of magnet links to operate on at once in batch mode
pub(crate) const MAGNET_LIMIT: usize = 50;
