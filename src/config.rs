use directories::ProjectDirs;
use rand::Rng;
use serde::{
    de::{Deserializer, Unexpected},
    Deserialize,
};
use std::fmt;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub(crate) struct Config {
    #[serde(default)]
    pub(crate) general: GeneralConfig,
    #[serde(default)]
    pub(crate) trackers: TrackersConfig,
    #[serde(default)]
    pub(crate) peers: PeersConfig,
}

impl Config {
    pub(crate) fn default_path() -> PathBuf {
        let Some(projdirs) = ProjectDirs::from("", "jwodder", "demagnetize") else {
            // Return something almost reasonable if $HOME can't be determined
            return ".config/demagnetize/config.toml".into();
        };
        projdirs.config_local_dir().join("config.toml")
    }

    pub(crate) fn load<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct GeneralConfig {
    #[serde(default = "default_batch_jobs")]
    batch_jobs: NonZeroUsize,
}

impl Default for GeneralConfig {
    fn default() -> GeneralConfig {
        GeneralConfig {
            batch_jobs: default_batch_jobs(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct TrackersConfig {
    #[serde(default)]
    local_port: LocalPort,

    #[serde(default = "default_numwant")]
    numwant: NonZeroU32,

    #[serde(default = "default_tracker_jobs_per_magnet")]
    jobs_per_magnet: NonZeroUsize,

    #[serde(
        default = "default_announce_timeout",
        deserialize_with = "deserialize_seconds"
    )]
    announce_timeout: Duration,

    #[serde(
        default = "default_shutdown_timeout",
        deserialize_with = "deserialize_seconds"
    )]
    shutdown_timeout: Duration,
}

impl Default for TrackersConfig {
    fn default() -> TrackersConfig {
        TrackersConfig {
            local_port: LocalPort::default(),
            numwant: default_numwant(),
            jobs_per_magnet: default_tracker_jobs_per_magnet(),
            announce_timeout: default_announce_timeout(),
            shutdown_timeout: default_shutdown_timeout(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct PeersConfig {
    #[serde(default = "default_peer_jobs_per_magnet")]
    jobs_per_magnet: NonZeroUsize,

    #[serde(
        default = "default_handshake_timeout",
        deserialize_with = "deserialize_seconds"
    )]
    handshake_timeout: Duration,
}

impl Default for PeersConfig {
    fn default() -> PeersConfig {
        PeersConfig {
            jobs_per_magnet: default_peer_jobs_per_magnet(),
            handshake_timeout: default_handshake_timeout(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalPort {
    Constant(u16),
    Range { low: u16, high: u16 },
}

impl LocalPort {
    pub(crate) fn generate<R: Rng>(&self, mut rng: R) -> u16 {
        match *self {
            LocalPort::Constant(p) => p,
            LocalPort::Range { low, high } => rng.random_range(low..=high),
        }
    }
}

impl Default for LocalPort {
    fn default() -> LocalPort {
        LocalPort::Range {
            low: 1025,
            high: 65535,
        }
    }
}

impl<'de> Deserialize<'de> for LocalPort {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = LocalPort;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "either a single port number or two ascending port numbers separated by a hyphen",
                )
            }

            fn visit_u16<E>(self, p: u16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(LocalPort::Constant(p))
            }

            fn visit_str<E>(self, input: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if input.chars().all(|c| c.is_ascii_digit()) {
                    let Ok(p) = input.parse::<u16>() else {
                        return Err(E::invalid_value(Unexpected::Str(input), &self));
                    };
                    Ok(LocalPort::Constant(p))
                } else {
                    let Some((pre, post)) = input.split_once('-') else {
                        return Err(E::invalid_value(Unexpected::Str(input), &self));
                    };
                    let low = pre.trim().parse::<u16>().ok();
                    let high = post.trim().parse::<u16>().ok();
                    let Some((low, high)) = low.zip(high).filter(|(l, h)| l <= h) else {
                        return Err(E::invalid_value(Unexpected::Str(input), &self));
                    };
                    Ok(LocalPort::Range { low, high })
                }
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("failed to read configuration file")]
    Read(#[from] std::io::Error),
    #[error("failed to parse configuration file")]
    Parse(#[from] toml::de::Error),
}

fn default_batch_jobs() -> NonZeroUsize {
    NonZeroUsize::new(50).expect("default general.batch-jobs should be nonzero")
}

fn default_numwant() -> NonZeroU32 {
    NonZeroU32::new(50).expect("default trackers.numwant should be nonzero")
}

fn default_tracker_jobs_per_magnet() -> NonZeroUsize {
    NonZeroUsize::new(30).expect("default trackers.jobs-per-magnet should be nonzero")
}

fn default_announce_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_shutdown_timeout() -> Duration {
    Duration::from_secs(3)
}

fn default_peer_jobs_per_magnet() -> NonZeroUsize {
    NonZeroUsize::new(30).expect("default peers.jobs-per-magnet should be nonzero")
}

fn default_handshake_timeout() -> Duration {
    Duration::from_secs(60)
}

fn deserialize_seconds<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    u64::deserialize(deserializer).map(Duration::from_secs)
}
