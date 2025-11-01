use crate::peer::CryptoMode;
use crate::tracker::TrackerCrypto;
use rand::Rng;
use serde::{
    Deserialize,
    de::{Deserializer, Unexpected},
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
    // Returns `None` if $HOME cannot be determined
    pub(crate) fn default_path() -> Option<PathBuf> {
        Some(
            dirs::config_local_dir()?
                .join("demagnetize")
                .join("config.toml"),
        )
    }

    pub(crate) fn load<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(Into::into)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, rename_all = "kebab-case")]
pub(crate) struct GeneralConfig {
    /// Maximum number of magnet links to operate on at once in batch mode
    pub(crate) batch_jobs: NonZeroUsize,

    pub(crate) encrypt: CryptoPreference,
}

impl Default for GeneralConfig {
    fn default() -> GeneralConfig {
        GeneralConfig {
            batch_jobs: NonZeroUsize::new(50)
                .expect("default general.batch-jobs should be nonzero"),
            encrypt: CryptoPreference::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, rename_all = "kebab-case")]
pub(crate) struct TrackersConfig {
    pub(crate) local_port: LocalPort,

    /// Number of peers to request per tracker
    pub(crate) numwant: NonZeroU32,

    /// Maximum number of trackers per magnet link to communicate with at once
    pub(crate) jobs_per_magnet: NonZeroUsize,

    /// Overall timeout for interacting with a tracker
    #[serde(deserialize_with = "deserialize_seconds")]
    pub(crate) announce_timeout: Duration,

    /// Timeout for sending & receiving a "stopped" announcement to a tracker
    #[serde(deserialize_with = "deserialize_seconds")]
    pub(crate) shutdown_timeout: Duration,
}

impl Default for TrackersConfig {
    fn default() -> TrackersConfig {
        TrackersConfig {
            local_port: LocalPort::default(),
            numwant: NonZeroU32::new(50).expect("default trackers.numwant should be nonzero"),
            jobs_per_magnet: NonZeroUsize::new(30)
                .expect("default trackers.jobs-per-magnet should be nonzero"),
            announce_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(3),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, rename_all = "kebab-case")]
pub(crate) struct PeersConfig {
    /// Maximum number of peers per magnet link to interact with at once
    pub(crate) jobs_per_magnet: NonZeroUsize,

    /// Timeout for connecting to a peer and performing the BitTorrent
    /// handshake and extended handshake
    #[serde(deserialize_with = "deserialize_seconds")]
    pub(crate) handshake_timeout: Duration,

    /// Timeout for receiving packet 2 from server during encryption handshake
    #[serde(deserialize_with = "deserialize_seconds")]
    pub(crate) dh_exchange_timeout: Duration,
}

impl Default for PeersConfig {
    fn default() -> PeersConfig {
        PeersConfig {
            jobs_per_magnet: NonZeroUsize::new(30)
                .expect("default peers.jobs-per-magnet should be nonzero"),
            handshake_timeout: Duration::from_secs(60),
            dh_exchange_timeout: crate::peer::msepe::DEFAULT_DH_EXCHANGE_TIMEOUT,
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

macro_rules! try_visit_int {
    ($($t:ty, $visit:ident),* $(,)?) => {
        $(
            fn $visit<E>(self, p: $t) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                u16::try_from(p).map(LocalPort::Constant).map_err(|_| {
                    E::invalid_value(
                        Unexpected::Signed(p.into()),
                        &"port number out of range; must be from 0 to 65535",
                    )
                })
            }
        )*
    }
}

macro_rules! try_visit_uint {
    ($($t:ty, $visit:ident),* $(,)?) => {
        $(
            fn $visit<E>(self, p: $t) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                u16::try_from(p).map(LocalPort::Constant).map_err(|_| {
                    E::invalid_value(
                        Unexpected::Unsigned(p.into()),
                        &"port number out of range; must be from 0 to 65535",
                    )
                })
            }
        )*
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

            fn visit_u8<E>(self, p: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(LocalPort::Constant(u16::from(p)))
            }

            fn visit_u16<E>(self, p: u16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(LocalPort::Constant(p))
            }

            try_visit_int!(i8, visit_i8, i16, visit_i16, i32, visit_i32, i64, visit_i64);
            try_visit_uint!(u32, visit_u32, u64, visit_u64);

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

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CryptoPreference {
    Always,
    #[default]
    Prefer,
    IfRequired,
    Never,
}

impl CryptoPreference {
    pub(crate) fn get_tracker_crypto(&self) -> TrackerCrypto {
        match self {
            CryptoPreference::Always => TrackerCrypto::Required,
            CryptoPreference::Never => TrackerCrypto::Plain,
            _ => TrackerCrypto::Supported,
        }
    }

    pub(crate) fn get_crypto_mode(&self, requires_crypto: bool) -> Option<CryptoMode> {
        match (self, requires_crypto) {
            (CryptoPreference::Always, _) => Some(CryptoMode::Encrypt),
            (CryptoPreference::Prefer, true) => Some(CryptoMode::Encrypt),
            (CryptoPreference::Prefer, false) => Some(CryptoMode::Prefer),
            (CryptoPreference::IfRequired, true) => Some(CryptoMode::Encrypt),
            (CryptoPreference::IfRequired, false) => Some(CryptoMode::Plain),
            (CryptoPreference::Never, true) => None,
            (CryptoPreference::Never, false) => Some(CryptoMode::Plain),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    #[error("error reading configuration file")]
    Read(#[from] std::io::Error),
    #[error("error parsing configuration file")]
    Parse(#[from] toml::de::Error),
}

fn deserialize_seconds<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    u64::deserialize(deserializer).map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn default_config() {
        let cfg = Config::default();
        assert_eq!(
            cfg,
            Config {
                general: GeneralConfig {
                    batch_jobs: NonZeroUsize::new(50).unwrap(),
                    encrypt: CryptoPreference::Prefer,
                },
                trackers: TrackersConfig {
                    local_port: LocalPort::default(),
                    numwant: NonZeroU32::new(50).unwrap(),
                    jobs_per_magnet: NonZeroUsize::new(30).unwrap(),
                    announce_timeout: Duration::from_secs(30),
                    shutdown_timeout: Duration::from_secs(3),
                },
                peers: PeersConfig {
                    jobs_per_magnet: NonZeroUsize::new(30).unwrap(),
                    handshake_timeout: Duration::from_secs(60),
                    dh_exchange_timeout: Duration::from_secs(30),
                }
            }
        );
    }

    fn load_config(cfg: &str) -> Result<Config, ConfigError> {
        let mut tmpfile = NamedTempFile::new().unwrap();
        tmpfile.write_all(cfg.as_bytes()).unwrap();
        tmpfile.flush().unwrap();
        Config::load(tmpfile.path())
    }

    #[test]
    fn empty_config() {
        let cfg = load_config("").unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn int_local_port() {
        let cfg = load_config("[trackers]\nlocal-port = 60069\n").unwrap();
        assert_eq!(
            cfg,
            Config {
                trackers: TrackersConfig {
                    local_port: LocalPort::Constant(60069),
                    ..TrackersConfig::default()
                },
                ..Config::default()
            }
        );
    }

    #[test]
    fn int_str_local_port() {
        let cfg = load_config("[trackers]\nlocal-port = \"60069\"\n").unwrap();
        assert_eq!(
            cfg,
            Config {
                trackers: TrackersConfig {
                    local_port: LocalPort::Constant(60069),
                    ..TrackersConfig::default()
                },
                ..Config::default()
            }
        );
    }

    #[test]
    fn local_port_range() {
        let cfg = load_config("[trackers]\nlocal-port = \"3000-4000\"\n").unwrap();
        assert_eq!(
            cfg,
            Config {
                trackers: TrackersConfig {
                    local_port: LocalPort::Range {
                        low: 3000,
                        high: 4000
                    },
                    ..TrackersConfig::default()
                },
                ..Config::default()
            }
        );
    }

    #[test]
    fn local_port_spaced_range() {
        let cfg = load_config("[trackers]\nlocal-port = \"3000 - 4000\"\n").unwrap();
        assert_eq!(
            cfg,
            Config {
                trackers: TrackersConfig {
                    local_port: LocalPort::Range {
                        low: 3000,
                        high: 4000
                    },
                    ..TrackersConfig::default()
                },
                ..Config::default()
            }
        );
    }

    #[test]
    fn local_port_eq_range() {
        let cfg = load_config("[trackers]\nlocal-port = \"3000-3000\"\n").unwrap();
        assert_eq!(
            cfg,
            Config {
                trackers: TrackersConfig {
                    local_port: LocalPort::Range {
                        low: 3000,
                        high: 3000
                    },
                    ..TrackersConfig::default()
                },
                ..Config::default()
            }
        );
    }

    #[test]
    fn descending_local_port_range() {
        assert!(load_config("[trackers]\nlocal-port = \"4000-3000\"\n").is_err());
    }

    #[test]
    fn zero_duration() {
        let cfg = load_config("[trackers]\nshutdown-timeout = 0\n").unwrap();
        assert_eq!(
            cfg,
            Config {
                trackers: TrackersConfig {
                    shutdown_timeout: Duration::from_secs(0),
                    ..TrackersConfig::default()
                },
                ..Config::default()
            }
        );
    }

    #[test]
    fn full_config() {
        let cfg = load_config(concat!(
            "[general]\n",
            "batch-jobs = 100\n",
            "encrypt = \"if-required\"\n",
            "\n",
            "[trackers]\n",
            "announce-timeout = 45\n",
            "jobs-per-magnet = 42\n",
            "local-port = \"10000-65535\"\n",
            "numwant = 75\n",
            "shutdown-timeout = 5\n",
            "\n",
            "[peers]\n",
            "dh-exchange-timeout = 10\n",
            "handshake-timeout = 120\n",
            "jobs-per-magnet = 23\n",
        ))
        .unwrap();
        assert_eq!(
            cfg,
            Config {
                general: GeneralConfig {
                    batch_jobs: NonZeroUsize::new(100).unwrap(),
                    encrypt: CryptoPreference::IfRequired,
                },
                trackers: TrackersConfig {
                    local_port: LocalPort::Range {
                        low: 10000,
                        high: 65535
                    },
                    numwant: NonZeroU32::new(75).unwrap(),
                    jobs_per_magnet: NonZeroUsize::new(42).unwrap(),
                    announce_timeout: Duration::from_secs(45),
                    shutdown_timeout: Duration::from_secs(5),
                },
                peers: PeersConfig {
                    jobs_per_magnet: NonZeroUsize::new(23).unwrap(),
                    handshake_timeout: Duration::from_secs(120),
                    dh_exchange_timeout: Duration::from_secs(10),
                }
            }
        );
    }

    #[test]
    fn generate_local_port_single_range() {
        let lp = LocalPort::Range {
            low: 1025,
            high: 1025,
        };
        assert_eq!(lp.generate(rand::rng()), 1025);
    }
}
