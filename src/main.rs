#![allow(dead_code)]
mod asyncutil;
mod consts;
mod peer;
mod tracker;
mod types;
mod util;
use crate::asyncutil::received_stream;
use crate::consts::NUMWANT;
use crate::tracker::Tracker;
use crate::types::{InfoHash, LocalPeer};
use anstream::AutoStream;
use anstyle::{AnsiColor, Style};
use clap::{Parser, Subcommand};
use futures::stream::StreamExt;
use log::{Level, LevelFilter};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
}

impl Command {
    async fn run(self) -> ExitCode {
        match self {
            Command::QueryTracker { tracker, info_hash } => {
                let local = LocalPeer::generate(rand::thread_rng());
                // TODO: Log local details?
                let ok = Arc::new(AtomicBool::new(true));
                let inner_ok = ok.clone();
                let stream =
                    received_stream(usize::try_from(NUMWANT).unwrap(), |sender| async move {
                        if let Err(e) = tracker.get_peers(&info_hash, &local, sender).await {
                            // TODO: Show chain of source errors
                            log::error!("Error communicating with tracker: {e}");
                            inner_ok.store(true, Ordering::Relaxed);
                        }
                    });
                tokio::pin!(stream);
                while let Some(peer) = stream.next().await {
                    println!("{peer}");
                }
                if ok.load(Ordering::Relaxed) {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
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
                "{}[{:<5}] {}{}",
                style.render(),
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
