use crate::peer::extensions::Extension;

/// "left" value to use when announcing to a tracker for a torrent we have only
/// the magnet link of
pub(crate) const LEFT: u64 = 65535;

/// Prefix for generated peer IDs (calculated from package version by `build.rs` script)
pub(crate) static PEER_ID_PREFIX: &str = env!("PEER_ID_PREFIX");

/// Size of buffer for receiving incoming UDP packets.  Any packets longer than
/// this are truncated.
pub(crate) const UDP_PACKET_LEN: usize = 65535;

/// Maximum metadata size to accept
pub(crate) const MAX_INFO_LENGTH: usize = 20 << 20; // 20 MiB

/// BitTorrent protocol extensions supported by demagnetize
pub(crate) const SUPPORTED_EXTENSIONS: [Extension; 2] = [Extension::Bep10, Extension::Fast];

/// Extended message ID to declare for receiving BEP 9 messages
pub(crate) const UT_METADATA: u8 = 42;

/// Client string to send in extended handshakes and to use as the "Created by"
/// field in Torrent files
pub(crate) static CLIENT: &str = concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"));

/// Maximum length of a message to accept from a peer
pub(crate) const MAX_PEER_MSG_LEN: usize = 65535;
