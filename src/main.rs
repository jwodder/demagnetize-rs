mod asyncutil;
mod consts;
mod magnet;
mod peer;
mod torrent;
mod tracker;
mod types;
mod util;
use crate::asyncutil::{BufferedTasks, ShutdownGroup};
use crate::consts::{MAGNET_LIMIT, TRACKER_STOP_TIMEOUT};
use crate::magnet::{parse_magnets_file, Magnet};
use crate::peer::Peer;
use crate::torrent::{PathTemplate, TorrentFile};
use crate::tracker::Tracker;
use crate::types::{InfoHash, LocalPeer};
use crate::util::ErrorChain;
use anstream::AutoStream;
use anstyle::{AnsiColor, Style};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use log::{Level, LevelFilter};
use patharg::InputArg;
use std::process::ExitCode;
use std::sync::Arc;

/// Convert magnet links to .torrent files
#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(version)]
struct Arguments {
    /// Set logging level
    #[arg(
        short,
        long,
        default_value = "INFO",
        value_name = "OFF|ERROR|WARN|INFO|DEBUG|TRACE"
    )]
    log_level: LevelFilter,

    #[command(subcommand)]
    command: Command,
}

impl Arguments {
    async fn run(self) -> ExitCode {
        init_logging(self.log_level);
        self.command.run().await
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
enum Command {
    /// Download the .torrent file for a single magnet link
    Get {
        /// Save the .torrent file to the given path.
        ///
        /// The path may contain a `{name}` placeholder, which will be replaced
        /// by the (sanitized) name of the torrent, and/or a `{hash}`
        /// placeholder, which will be replaced by the torrent's info hash in
        /// hexadecimal.
        #[arg(short, long, default_value = "{name}.torrent")]
        outfile: PathTemplate,

        magnet: Magnet,
    },
    /// Download the .torrent files for a file of magnet links
    Batch {
        /// Save the .torrent files to the given path template.
        ///
        /// The path template may contain a `{name}` placeholder, which will be
        /// replaced by the (sanitized) name of each torrent, and/or a `{hash}`
        /// placeholder, which will be replaced by each torrent's info hash in
        /// hexadecimal.
        #[arg(short, long, default_value = "{name}.torrent")]
        outfile: PathTemplate,

        /// A file listing magnet links, one per line.  Empty lines and lines
        /// starting with '#' are ignored.
        file: InputArg,
    },
    /// Fetch peers for an info hash from a specific tracker
    QueryTracker {
        /// The tracker to scrape, as an HTTP or UDP URL.
        tracker: Tracker,

        /// The info hash of the torrent to get peers for.
        ///
        /// This must be either a 40-character hex string or a 32-character
        /// base32 string.
        info_hash: InfoHash,
    },
    /// Fetch torrent metadata for an info hash from a specific peer
    ///
    /// Note that the resulting .torrent file will not contain any trackers.
    QueryPeer {
        /// Save the .torrent file to the given path.
        ///
        /// The path may contain a `{name}` placeholder, which will be replaced
        /// by the (sanitized) name of the torrent, and/or a `{hash}`
        /// placeholder, which will be replaced by the torrent's info hash in
        /// hexadecimal.
        #[arg(short, long, default_value = "{name}.torrent")]
        outfile: PathTemplate,

        /// The peer to get metadata from, in the form "IP:PORT" (or
        /// "[IP]:PORT" for IPv6).
        peer: Peer,

        /// The info hash of the torrent to get metadata for.
        ///
        /// This must be either a 40-character hex string or a 32-character
        /// base32 string.
        info_hash: InfoHash,
    },
}

impl Command {
    async fn run(self) -> ExitCode {
        let local = LocalPeer::generate(rand::rng());
        log::debug!("Using local peer details: {local}");
        match self {
            Command::Get { outfile, magnet } => {
                let group = Arc::new(ShutdownGroup::new());
                let r = if let Err(e) = magnet
                    .download_torrent_file(Arc::new(outfile), local, Arc::clone(&group))
                    .await
                {
                    log::error!("Failed to download torrent file: {}", ErrorChain(e));
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                };
                group.shutdown(TRACKER_STOP_TIMEOUT).await;
                r
            }
            Command::Batch { outfile, file } => {
                let magnets = match parse_magnets_file(file).await {
                    Ok(magnets) => magnets,
                    Err(e) => {
                        log::error!("Error reading magnets file: {}", ErrorChain(e));
                        return ExitCode::FAILURE;
                    }
                };
                if magnets.is_empty() {
                    log::info!("No magnet links supplied");
                    return ExitCode::SUCCESS;
                }
                let group = Arc::new(ShutdownGroup::new());
                let mut success = 0usize;
                let mut total = 0usize;
                let outfile = Arc::new(outfile);
                let mut tasks = BufferedTasks::from_iter(
                    MAGNET_LIMIT,
                    magnets.into_iter().map(|magnet| {
                        let gr = Arc::clone(&group);
                        let outf = Arc::clone(&outfile);
                        async move {
                            if let Err(e) = magnet.download_torrent_file(outf, local, gr).await {
                                log::error!(
                                    "Failed to download torrent file for {magnet}: {}",
                                    ErrorChain(e)
                                );
                                false
                            } else {
                                true
                            }
                        }
                    }),
                );
                while let Some(b) = tasks.next().await {
                    if b {
                        success += 1;
                    }
                    total += 1;
                }
                log::info!(
                    "{success}/{total} magnet links successfully converted to torrent files"
                );
                group.shutdown(TRACKER_STOP_TIMEOUT).await;
                if success == total {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Command::QueryTracker { tracker, info_hash } => {
                let group = Arc::new(ShutdownGroup::new());
                let r = match tracker
                    .get_peers(info_hash, local, Arc::clone(&group))
                    .await
                {
                    Ok(peers) => {
                        for p in peers {
                            println!("{}", p.address);
                        }
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        log::error!("Error communicating with tracker: {}", ErrorChain(e));
                        ExitCode::FAILURE
                    }
                };
                group.shutdown(TRACKER_STOP_TIMEOUT).await;
                r
            }
            Command::QueryPeer {
                outfile,
                peer,
                info_hash,
            } => match peer.get_metadata_info(info_hash, local).await {
                Ok(info) => {
                    let tf = TorrentFile::new(info, Vec::new());
                    if let Err(e) = tf.save(&outfile).await {
                        log::error!("Failed to write to file: {}", ErrorChain(e));
                        ExitCode::FAILURE
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    log::error!("Failed to fetch info from peer: {}", ErrorChain(e));
                    ExitCode::FAILURE
                }
            },
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    Arguments::parse().run().await
}

fn init_logging(log_level: LevelFilter) {
    let stderr: Box<dyn std::io::Write + Send> = Box::new(AutoStream::auto(std::io::stderr()));
    fern::Dispatch::new()
        .format(|out, message, record| {
            use AnsiColor::*;
            let style = match record.level() {
                Level::Error => Style::new().fg_color(Some(Red.into())),
                Level::Warn => Style::new().fg_color(Some(Yellow.into())),
                Level::Info => Style::new().bold(),
                Level::Debug => Style::new().fg_color(Some(Cyan.into())),
                Level::Trace => Style::new().fg_color(Some(Green.into())),
            };
            out.finish(format_args!(
                "{}{} [{:<5}] {}{}",
                style.render(),
                chrono::Local::now().format("%H:%M:%S"),
                record.level(),
                message,
                style.render_reset(),
            ));
        })
        .level(LevelFilter::Info)
        .level_for("demagnetize", log_level)
        .chain(stderr)
        .apply()
        .expect("no other logger should have been previously initialized");
}
