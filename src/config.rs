use serde::Deserialize;
use std::{error::Error, fs, io, path::Path};

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub server: Server,
    pub protection: Protection,
    pub limits: Limits,
    pub access: Access,
    pub storage: Storage,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Server {
    pub listen: String,
    pub path: String,
    pub max_body_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Protection {
    pub name_patterns: Vec<String>,
    pub case_insensitive: bool,
    pub proxy_types: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub short_window_secs: u64,
    pub short_max_connections: usize,
    pub long_window_secs: u64,
    pub long_max_connections: usize,
    pub rapid_retry_gap_ms: u64,
    pub rapid_retry_window_secs: u64,
    pub rapid_retry_max: usize,
    pub ban_duration_secs: u64,
    pub max_tracked_ips: usize,
    pub idle_ttl_secs: u64,
    pub cleanup_interval_secs: u64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Access {
    pub allow_cidrs: Vec<ipnet::IpNet>,
    pub deny_cidrs: Vec<ipnet::IpNet>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Storage {
    pub sqlite_path: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: Server::default(),
            protection: Protection::default(),
            limits: Limits::default(),
            access: Access::default(),
            storage: Storage::default(),
        }
    }
}
impl Default for Server {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9000".into(),
            path: "/handler".into(),
            max_body_bytes: 16_384,
        }
    }
}
impl Default for Protection {
    fn default() -> Self {
        Self {
            name_patterns: vec!["*ssh*".into(), "*rdp*".into()],
            case_insensitive: true,
            proxy_types: vec!["tcp".into(), "stcp".into(), "https".into(), "tcpmux".into()],
        }
    }
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            short_window_secs: 10,
            short_max_connections: 6,
            long_window_secs: 60,
            long_max_connections: 20,
            rapid_retry_gap_ms: 1500,
            rapid_retry_window_secs: 30,
            rapid_retry_max: 4,
            ban_duration_secs: 3600,
            max_tracked_ips: 100_000,
            idle_ttl_secs: 600,
            cleanup_interval_secs: 60,
        }
    }
}
impl Default for Storage {
    fn default() -> Self {
        Self {
            sqlite_path: "./frp-connection-guard.sqlite3".into(),
        }
    }
}

impl Settings {
    pub fn read(path: &Path) -> Result<Self, Box<dyn Error>> {
        let config: Self = toml::from_str(&fs::read_to_string(path)?)?;
        config.validate().map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.server.path.starts_with('/') || self.server.path.contains('?') {
            return Err("server.path must start with / and must not contain ?".into());
        }
        if self.server.max_body_bytes < 256 || self.server.max_body_bytes > 1_048_576 {
            return Err("server.max_body_bytes must be between 256 and 1048576".into());
        }
        if self.protection.name_patterns.is_empty() {
            return Err("protection.name_patterns cannot be empty".into());
        }
        if self.protection.proxy_types.is_empty() {
            return Err("protection.proxy_types cannot be empty".into());
        }
        let l = &self.limits;
        if [
            l.short_window_secs,
            l.long_window_secs,
            l.rapid_retry_gap_ms,
            l.rapid_retry_window_secs,
            l.idle_ttl_secs,
            l.cleanup_interval_secs,
        ].contains(&0) {
            return Err("all window, gap, idle and cleanup durations must be positive".into());
        }
        if l.ban_duration_secs == 0 || l.ban_duration_secs > 315_360_000 {
            return Err("limits.ban_duration_secs must be between 1 and 315360000".into());
        }
        if l.short_max_connections == 0
            || l.long_max_connections == 0
            || l.rapid_retry_max == 0
            || l.max_tracked_ips == 0
        {
            return Err("connection limits and max_tracked_ips must be positive".into());
        }
        if self.storage.sqlite_path.trim().is_empty() {
            return Err("storage.sqlite_path cannot be empty".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Settings::default().validate().unwrap();
    }

    #[test]
    fn reject_zero_window() {
        let mut config = Settings::default();
        config.limits.short_window_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn parse_custom_globs_and_cidrs() {
        let s: Settings = toml::from_str(
            "[protection]\nname_patterns = ['*SSH*']\n[access]\ndeny_cidrs = ['2001:db8::/32']",
        ).unwrap();
        assert_eq!(s.protection.name_patterns, vec!["*SSH*"]);
        assert_eq!(s.access.deny_cidrs.len(), 1);
        s.validate().unwrap();
    }
}
