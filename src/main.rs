#![allow(dead_code)]
mod asyncutil;
mod consts;
mod peer;
mod torrent;
mod tracker;
mod types;
mod util;
use crate::peer::Peer;
use crate::tracker::Tracker;
use crate::types::{InfoHash, LocalPeer};
use crate::util::ErrorChain;
use anstream::AutoStream;
use anstyle::{AnsiColor, Style};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use log::{Level, LevelFilter};
use std::process::ExitCode;

/// Convert magnet links to .torrent files
#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[clap(version)]
struct Arguments {
    /// Set logging level
    #[clap(
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
    QueryTracker {
        tracker: Tracker,
        info_hash: InfoHash,
    },
    QueryPeer {
        peer: Peer,
        info_hash: InfoHash,
    },
}

impl Command {
    async fn run(self) -> ExitCode {
        match self {
            Command::QueryTracker { tracker, info_hash } => {
                let local = LocalPeer::generate(rand::thread_rng());
                // TODO: Log local details?
                match tracker.get_peers(&info_hash, &local).await {
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
                }
            }
            Command::QueryPeer { peer, info_hash } => {
                let local = LocalPeer::generate(rand::thread_rng());
                // TODO: Log local details?
                match peer.get_metadata_info(&info_hash, &local).await {
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
            ))
        })
        .level(LevelFilter::Info)
        .level_for("demagnetize", log_level)
        .chain(stderr)
        .apply()
        .unwrap();
}
