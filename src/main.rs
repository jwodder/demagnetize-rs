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
use crate::torrent::PathTemplate;
use crate::tracker::Tracker;
use crate::types::{InfoHash, LocalPeer};
use crate::util::ErrorChain;
use anstream::AutoStream;
use anstyle::{AnsiColor, Style};
use bytes::Bytes;
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
    /// Fetch peers for an info hash from a tracker
    #[command(hide = true)]
    QueryTracker {
        tracker: Tracker,
        info_hash: InfoHash,
    },
    /// Fetch torrent metadata for an info hash from a peer
    #[command(hide = true)]
    QueryPeer { peer: Peer, info_hash: InfoHash },
}

impl Command {
    async fn run(self) -> ExitCode {
        let local = LocalPeer::generate(rand::thread_rng());
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
                    "{}/{} magnet links successfully converted to torrent files",
                    success,
                    total
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
                            println!("{p}");
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
            Command::QueryPeer { peer, info_hash } => {
                match peer.get_metadata_info(info_hash, local).await {
                    Ok(info) => {
                        let filename = format!("{info_hash}.bencode");
                        log::info!("Saving info to {filename}");
                        if let Err(e) = std::fs::write(filename, Bytes::from(info)) {
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
                }
            }
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
