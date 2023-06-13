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
