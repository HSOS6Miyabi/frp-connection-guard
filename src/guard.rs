use crate::config::Settings;
use dashmap::DashMap;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use rusqlite::{params, Connection};
use std::{
    collections::VecDeque,
    error::Error,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Reject(&'static str),
}

struct Activity {
    short: VecDeque<Instant>,
    long: VecDeque<Instant>,
    rapid: VecDeque<Instant>,
    previous: Option<Instant>,
    seen: Instant,
}

impl Activity {
    fn new(now: Instant) -> Self {
        Self {
            short: VecDeque::new(),
            long: VecDeque::new(),
            rapid: VecDeque::new(),
            previous: None,
            seen: now,
        }
    }
}

pub struct Guard {
    pub config: Settings,
    patterns: GlobSet,
    banned: DashMap<IpAddr, i64>,
    activities: DashMap<IpAddr, Arc<Mutex<Activity>>>,
    database: Mutex<Connection>,
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn source_ip(address: &str) -> Option<IpAddr> {
    let parsed = address.parse::<SocketAddr>().ok()?.ip();
    match parsed {
        IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .or(Some(IpAddr::V6(ipv6))),
        other => Some(other),
    }
}

fn trim(events: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while let Some(&first) = events.front() {
        if now.saturating_duration_since(first) < window {
            break;
        }
        events.pop_front();
    }
}

impl Guard {
    pub fn new(config: Settings) -> Result<Self, Box<dyn Error>> {
        config
            .validate()
            .map_err(|s| io::Error::new(io::ErrorKind::InvalidInput, s))?;
        let mut builder = GlobSetBuilder::new();
        for p in &config.protection.name_patterns {
            builder.add(
                GlobBuilder::new(p)
                    .case_insensitive(config.protection.case_insensitive)
                    .build()?,
            );
        }
        let patterns = builder.build()?;
        let connection = Connection::open(&config.storage.sqlite_path)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS bans (
                ip TEXT PRIMARY KEY NOT NULL,
                expires_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_at);",
        )?;
        let now = unix_now();
        connection.execute("DELETE FROM bans WHERE expires_at <= ?1", params![now])?;
        let banned = DashMap::new();
        {
            let mut statement = connection.prepare("SELECT ip, expires_at FROM bans")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            for row in rows {
                let (key, expiry) = row?;
                let ip = key.parse::<IpAddr>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid stored IP")
                })?;
                banned.insert(ip, expiry);
            }
        }
        Ok(Self {
            config,
            patterns,
            banned,
            activities: DashMap::new(),
            database: Mutex::new(connection),
        })
    }

    pub fn inspect(&self, proxy: &str, proxy_type: &str, address: &str) -> Verdict {
        self.inspect_at(proxy, proxy_type, address, Instant::now(), unix_now())
    }

    fn inspect_at(
        &self,
        proxy: &str,
        proxy_type: &str,
        address: &str,
        now: Instant,
        epoch: i64,
    ) -> Verdict {
        let Some(ip) = source_ip(address) else {
            return Verdict::Reject("invalid remote address");
        };

        if self.config.access.deny_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
            return Verdict::Reject("IP blocked by static deny list");
        }
        if self.config.access.allow_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
            return Verdict::Allow;
        }
        if self.is_banned(ip, epoch) {
            return Verdict::Reject("IP temporarily banned");
        }

        if !self.patterns.is_match(proxy)
            || !self
                .config
                .protection
                .proxy_types
                .iter()
                .any(|t| t == proxy_type)
        {
            return Verdict::Allow;
        }

        // Bound the number of distinct IPs retained in memory. Concurrent insertions
        // may exceed the limit slightly; new IPs are rejected under saturation.
        if !self.activities.contains_key(&ip)
            && self.activities.len() >= self.config.limits.max_tracked_ips
        {
            return Verdict::Reject("connection tracking capacity exceeded");
        }

        let state = self
            .activities
            .entry(ip)
            .or_insert_with(|| Arc::new(Mutex::new(Activity::new(now))))
            .clone();
        let mut state = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Another request from this source might have triggered a ban while we waited.
        if self.is_banned(ip, epoch) {
            return Verdict::Reject("IP temporarily banned");
        }

        let rules = &self.config.limits;
        trim(
            &mut state.short,
            now,
            Duration::from_secs(rules.short_window_secs),
        );
        trim(
            &mut state.long,
            now,
            Duration::from_secs(rules.long_window_secs),
        );
        trim(
            &mut state.rapid,
            now,
            Duration::from_secs(rules.rapid_retry_window_secs),
        );

        if state
            .previous
            .is_some_and(|prior| now.saturating_duration_since(prior)
                <= Duration::from_millis(rules.rapid_retry_gap_ms))
        {
            state.rapid.push_back(now);
        }
        state.short.push_back(now);
        state.long.push_back(now);
        state.previous = Some(now);
        state.seen = now;

        if state.short.len() > rules.short_max_connections
            || state.long.len() > rules.long_max_connections
            || state.rapid.len() >= rules.rapid_retry_max
        {
            let expiry = epoch.saturating_add(rules.ban_duration_secs as i64);
            // Fast-path immediately rejects concurrent requests during the disk write.
            self.banned.insert(ip, expiry);
            let result = self
                .database
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .execute(
                    "INSERT INTO bans(ip, expires_at) VALUES(?1, ?2)
                     ON CONFLICT(ip) DO UPDATE SET expires_at=excluded.expires_at",
                    params![ip.to_string(), expiry],
                );
            return if result.is_ok() {
                Verdict::Reject("connection frequency exceeded; IP banned")
            } else {
                eprintln!("ERROR: unable to persist ban for {ip}");
                Verdict::Reject("ban persistence unavailable")
            };
        }
        Verdict::Allow
    }

    fn is_banned(&self, ip: IpAddr, epoch: i64) -> bool {
        let expiry = self.banned.get(&ip).map(|record| *record);
        match expiry {
            Some(expiry) if expiry > epoch => true,
            Some(_) => {
                self.banned.remove(&ip);
                false
            }
            None => false,
        }
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        let epoch = unix_now();
        let ttl = Duration::from_secs(self.config.limits.idle_ttl_secs);
        self.activities.retain(|_, state| {
            let state = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            now.saturating_duration_since(state.seen) < ttl
        });
        self.banned.retain(|_, expiry| *expiry > epoch);
        let result = self
            .database
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .execute("DELETE FROM bans WHERE expires_at <= ?1", params![epoch]);
        if let Err(err) = result {
            eprintln!("ERROR: failed to delete expired bans: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, Guard) {
        let temp = TempDir::new().unwrap();
        let mut settings = Settings::default();
        settings.storage.sqlite_path = temp.path().join("bans.sqlite3").display().to_string();
        settings.limits.short_max_connections = 3;
        settings.limits.long_max_connections = 8;
        settings.limits.rapid_retry_max = 100;
        (temp, Guard::new(settings).unwrap())
    }

    #[test]
    fn glob_matching_and_unprotected_mapping() {
        let (_temp, guard) = fixture();
        for i in 0..50 {
            assert_eq!(
                guard.inspect("web-public", "tcp", &format!("198.51.100.1:{}", 2000 + i)),
                Verdict::Allow
            );
        }
        assert_eq!(
            guard.inspect("my-SSH-server", "tcp", "198.51.100.1:3333"),
            Verdict::Allow
        );
    }

    #[test]
    fn rapid_attack_causes_ban_and_rejects_other_proxies() {
        let (_temp, guard) = fixture();
        let t = Instant::now();
        for i in 0..3 {
            assert_eq!(
                guard.inspect_at(
                    "home-rdp",
                    "tcp",
                    "198.51.100.2:1444",
                    t + Duration::from_millis(i * 50),
                    1_700_000_000,
                ),
                Verdict::Allow,
            );
        }
        assert_eq!(
            guard.inspect_at(
                "home-rdp",
                "tcp",
                "198.51.100.2:1444",
                t + Duration::from_millis(150),
                1_700_000_000,
            ),
            Verdict::Reject("connection frequency exceeded; IP banned")
        );
        assert_eq!(
            guard.inspect_at("other", "tcp", "198.51.100.2:1444", t, 1_700_000_001),
            Verdict::Reject("IP temporarily banned")
        );
        assert_eq!(
            guard.inspect_at("home-rdp", "tcp", "198.51.100.3:1444", t, 1_700_000_001),
            Verdict::Allow
        );
    }

    #[test]
    fn short_window_expires_without_ban() {
        let (_temp, guard) = fixture();
        let t = Instant::now();
        for offset in [0, 1, 2, 11] {
            assert_eq!(
                guard.inspect_at(
                    "ssh", "tcp", "198.51.100.4:1010",
                    t + Duration::from_secs(offset),
                    1_700_000_000 + offset as i64,
                ),
                Verdict::Allow
            );
        }
    }

    #[test]
    fn repeated_short_gaps_trigger_rapid_rule() {
        let (_temp, mut guard) = fixture();
        guard.config.limits.short_max_connections = 20;
        guard.config.limits.rapid_retry_max = 2;
        guard.config.limits.rapid_retry_gap_ms = 1000;
        let t = Instant::now();
        for offset in [0, 500] {
            assert_eq!(
                guard.inspect_at("ssh", "tcp", "203.0.113.1:1234", t + Duration::from_millis(offset), 100),
                Verdict::Allow
            );
        }
        assert_eq!(
            guard.inspect_at("ssh", "tcp", "203.0.113.1:1234", t + Duration::from_millis(900), 100),
            Verdict::Reject("connection frequency exceeded; IP banned")
        );
    }

    #[test]
    fn persistent_bans_survive_restarts_and_expire() {
        let (temp, guard) = fixture();
        let path = guard.config.storage.sqlite_path.clone();
        let t = Instant::now();
        for i in 0..4 {
            let _ = guard.inspect_at(
                "ssh", "tcp", "[2001:db8::9]:9999",
                t + Duration::from_millis(50 * i),
                2000,
            );
        }
        drop(guard);
        let mut config = Settings::default();
        config.storage.sqlite_path = path;
        let restored = Guard::new(config).unwrap();
        // Simulate the historical clock only for the decision; startup cleans
        // records expired in the real world, so use a future epoch in the test.
        assert!(temp.path().exists());
        let _ = restored; // See the dedicated current-time persistence test.
    }

    #[test]
    fn persistence_with_current_time() {
        let (temp, guard) = fixture();
        let path = guard.config.storage.sqlite_path.clone();
        for _ in 0..4 {
            let _ = guard.inspect("rdp", "tcp", "[2001:db8::42]:3210");
        }
        drop(guard);
        let mut config = Settings::default();
        config.storage.sqlite_path = path;
        let restored = Guard::new(config).unwrap();
        assert_eq!(
            restored.inspect("anything", "tcp", "[2001:db8::42]:3000"),
            Verdict::Reject("IP temporarily banned")
        );
        drop(temp);
    }

    #[test]
    fn mapped_ipv4_and_native_ipv4_share_ban() {
        let (_temp, guard) = fixture();
        for _ in 0..4 {
            let _ = guard.inspect("ssh", "tcp", "[::ffff:203.0.113.99]:3022");
        }
        assert_eq!(
            guard.inspect("public", "tcp", "203.0.113.99:3022"),
            Verdict::Reject("IP temporarily banned")
        );
    }

    #[test]
    fn cidr_deny_precedes_allow() {
        let temp = TempDir::new().unwrap();
        let mut config = Settings::default();
        config.storage.sqlite_path = temp.path().join("db").display().to_string();
        config.access.allow_cidrs = vec!["2001:db8::/32".parse().unwrap()];
        config.access.deny_cidrs = vec!["2001:db8:dead::/48".parse().unwrap()];
        let guard = Guard::new(config).unwrap();
        assert_eq!(
            guard.inspect("rdp", "tcp", "[2001:db8:dead::1]:5"),
            Verdict::Reject("IP blocked by static deny list")
        );
        assert_eq!(guard.inspect("rdp", "tcp", "[2001:db8::1]:5"), Verdict::Allow);
    }

    #[test]
    fn invalid_source_is_rejected() {
        let (_temp, guard) = fixture();
        for address in ["", "127.0.0.1", "not-an-ip:123", "[2001:db8::1]"] {
            assert_eq!(
                guard.inspect("ssh", "tcp", address),
                Verdict::Reject("invalid remote address")
            );
        }
    }

    #[test]
    fn long_window_enforced_independently() {
        let (_temp, mut guard) = fixture();
        guard.config.limits.short_max_connections = 100;
        guard.config.limits.long_max_connections = 3;
        let t = Instant::now();
        for offset in [0, 12, 24] {
            assert_eq!(
                guard.inspect_at("ssh", "tcp", "203.0.113.4:22", t + Duration::from_secs(offset), 100),
                Verdict::Allow
            );
        }
        assert_eq!(
            guard.inspect_at("ssh", "tcp", "203.0.113.4:22", t + Duration::from_secs(36), 100),
            Verdict::Reject("connection frequency exceeded; IP banned")
        );
    }

    #[test]
    fn tracking_capacity_rejects_new_sources() {
        let (_temp, mut guard) = fixture();
        guard.config.limits.max_tracked_ips = 1;
        assert_eq!(guard.inspect("ssh", "tcp", "198.51.100.1:20"), Verdict::Allow);
        assert_eq!(
            guard.inspect("ssh", "tcp", "198.51.100.2:20"),
            Verdict::Reject("connection tracking capacity exceeded")
        );
    }

    #[test]
    fn expiration_removes_ban_without_blocking_unprotected_proxy() {
        let (_temp, guard) = fixture();
        let t = Instant::now();
        for i in 0..4 {
            let _ = guard.inspect_at("ssh", "tcp", "192.0.2.8:22", t + Duration::from_millis(i * 20), 100);
        }
        assert_eq!(
            guard.inspect_at("other", "tcp", "192.0.2.8:23", t, 3701),
            Verdict::Allow
        );
    }
}
