mod app;
mod asyncutil;
mod config;
mod consts;
mod magnet;
mod peer;
mod torrent;
mod tracker;
mod types;
mod util;
use crate::app::App;
use crate::asyncutil::BufferedTasks;
use crate::config::{Config, ConfigError};
use crate::magnet::{parse_magnets_file, Magnet};
use crate::peer::{CryptoMode, Peer};
use crate::torrent::{PathTemplate, TorrentFile};
use crate::tracker::{Tracker, TrackerCrypto};
use crate::types::InfoHash;
use crate::util::ErrorChain;
use anstream::AutoStream;
use anstyle::{AnsiColor, Style};
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use log::{Level, LevelFilter};
use patharg::InputArg;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

/// Convert magnet links to .torrent files
#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(version)]
struct Arguments {
    /// Read program configuration from the given file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Set logging level
    #[arg(
        short,
        long,
        default_value = "INFO",
        value_name = "OFF|ERROR|WARN|INFO|DEBUG|TRACE"
    )]
    log_level: LevelFilter,

    /// Do not read any configuration files
    #[arg(long, conflicts_with = "config")]
    no_config: bool,

    #[command(subcommand)]
    command: Command,
}

impl Arguments {
    async fn run(mut self) -> ExitCode {
        init_logging(self.log_level);
        let cfg = if self.no_config {
            Config::default()
        } else {
            let (cfgpath, defpath) = if let Some(p) = self.config.take() {
                (p, false)
            } else if let Some(p) = Config::default_path() {
                (p, true)
            } else {
                log::error!("Failed to locate configuration file: could not determine user's home directory");
                return ExitCode::FAILURE;
            };
            log::debug!(
                "Reading program configuration from {} ...",
                cfgpath.display()
            );
            match Config::load(&cfgpath) {
                Ok(cfg) => cfg,
                Err(ConfigError::Read(e))
                    if e.kind() == std::io::ErrorKind::NotFound && defpath =>
                {
                    log::debug!(
                        "Default configuration file does not exist; using default settings"
                    );
                    Config::default()
                }
                Err(e) => {
                    log::error!(
                        "Failed to get program configuration from file {}: {}",
                        cfgpath.display(),
                        ErrorChain(e)
                    );
                    return ExitCode::FAILURE;
                }
            }
        };
        let app = Arc::new(App::new(cfg, rand::rng()));
        log::debug!("Using local peer details: {}", app.local);
        let r = self.command.run(Arc::clone(&app)).await;
        app.shutdown().await;
        r
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
        /// Output peers as JSON objects, one per line
        #[arg(short = 'J', long)]
        json: bool,

        /// Do not tell the tracker anything about our encryption support
        #[arg(
            long,
            conflicts_with = "require_crypto",
            conflicts_with = "support_crypto"
        )]
        no_crypto: bool,

        /// Tell the tracker that we require peers with encryption support
        #[arg(long)]
        require_crypto: bool,

        /// Tell the tracker that we support the encrypted peer protocol
        #[arg(long, conflicts_with = "require_crypto")]
        support_crypto: bool,

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
        /// Create an encrypted connection to the peer
        #[arg(long)]
        encrypt: bool,

        /// Create an unencrypted connection to the peer
        #[arg(long, conflicts_with = "encrypt")]
        no_encrypt: bool,

        /// Save the .torrent file to the given path.
        ///
        /// The path may contain a `{name}` placeholder, which will be replaced
        /// by the (sanitized) name of the torrent, and/or a `{hash}`
        /// placeholder, which will be replaced by the torrent's info hash in
        /// hexadecimal.
        #[arg(short, long, default_value = "{name}.torrent")]
        outfile: PathTemplate,

        /// Attempt to create an encrypted connection to the peer; if that
        /// fails, try again without encryption
        #[arg(long, conflicts_with = "encrypt", conflicts_with = "no_encrypt")]
        prefer_encrypt: bool,

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
    async fn run(self, app: Arc<App>) -> ExitCode {
        match self {
            Command::Get { outfile, magnet } => {
                if let Err(e) = magnet
                    .download_torrent_file(Arc::new(outfile), Arc::clone(&app))
                    .await
                {
                    log::error!("Failed to download torrent file: {}", ErrorChain(e));
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
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
                let mut success = 0usize;
                let mut total = 0usize;
                let outfile = Arc::new(outfile);
                let mut tasks = BufferedTasks::from_iter(
                    app.cfg.general.batch_jobs.get(),
                    magnets.into_iter().map(|magnet| {
                        let app = Arc::clone(&app);
                        let outf = Arc::clone(&outfile);
                        async move {
                            if let Err(e) = magnet.download_torrent_file(outf, app).await {
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
                if success == total {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Command::QueryTracker {
                json,
                tracker,
                info_hash,
                no_crypto,
                require_crypto,
                support_crypto,
            } => {
                let tracker_crypto = match (require_crypto, support_crypto, no_crypto) {
                    (true, _, _) => Some(TrackerCrypto::Required),
                    (false, true, _) => Some(TrackerCrypto::Supported),
                    (false, false, true) => Some(TrackerCrypto::Plain),
                    (false, false, false) => None,
                };
                let r = match tracker
                    .peer_getter(info_hash, Arc::clone(&app))
                    .tracker_crypto(tracker_crypto)
                    .run()
                    .await
                {
                    Ok(peers) => {
                        for p in peers {
                            if json {
                                println!("{}", p.display_json());
                            } else {
                                println!("{}", p.address);
                            }
                        }
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        log::error!("Error communicating with tracker: {}", ErrorChain(e));
                        ExitCode::FAILURE
                    }
                };
                r
            }
            Command::QueryPeer {
                outfile,
                peer,
                info_hash,
                encrypt,
                prefer_encrypt,
                no_encrypt,
            } => {
                let crypto_mode = match (encrypt, prefer_encrypt, no_encrypt) {
                    (true, _, _) => Some(CryptoMode::Encrypt),
                    (false, true, _) => Some(CryptoMode::Prefer),
                    (false, false, true) => Some(CryptoMode::Plain),
                    (false, false, false) => None,
                };
                match peer
                    .info_getter(info_hash, app)
                    .crypto_mode(crypto_mode)
                    .run()
                    .await
                {
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
