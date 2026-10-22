# frp Connection Guard

A standalone Rust server-management plugin for **frps**, designed to protect named SSH/RDP TCP mappings from repeated connection attempts. Requires an frp version that supports the **NewUserConn** HTTP plugin operation.

## Features

- Configurable proxy-name wildcard matching such as `*ssh*` and `*rdp*`, optionally case-insensitive.
- Parallel, per-source-IP accounting using DashMap and bounded time-window queues.
- Short-window, long-window and rapid-repeat thresholds.
- Automatic time-limited bans shared across protected and unprotected proxy names.
- IPv4, IPv6, and IPv4-mapped IPv6 normalization.
- Static CIDR deny/allow lists. Static deny has precedence over allow; allow bypasses dynamic restrictions.
- SQLite WAL persistence: committed bans survive process restarts; expired bans are removed.
- Configurable memory tracking capacity and idle-state cleanup.
- Local-only HTTP server and strict body-size limits.

**Technical limitations:** frps calls `NewUserConn` when a new visitor connection arrives, but does not expose a per-visitor connection-close callback in the server plugin protocol. Accordingly, rapid-retry detection uses inter-arrival gaps, not measured session duration or authentication failure results. Long-lived established connections are not terminated by a new ban; frps rejects subsequent connections. UDP, HTTP proxying, and any proxy type not invoking `NewUserConn` cannot be protected by this plugin. If real SSH/RDP authentication failure events are needed, deploy an additional authentication-log-based detector.

The frps server plugin client uses ordinary Go `net/http` and does not provide Unix-domain-socket configuration. The frpc `unix_domain_socket` *client plugin* is a separate feature. Use the local TCP listener shown below. Do not make it publicly accessible.

## Download prebuilt executables

Prebuilt archives are published at **[GitHub Releases](https://github.com/HSOS6Miyabi/frp-connection-guard/releases)** after all automated tests, release builds, and archive-integrity checks succeed.

| Platform | Architecture | Format |
|---|---|---|
| Linux | x86_64 (AMD64), AArch64 (ARM64) | `.tar.gz` |
| Windows | x86_64 (AMD64), ARM64 | `.zip` |
| macOS | Intel x86_64, Apple Silicon ARM64 | `.tar.gz` |

Each archive contains the executable, `config/guard.toml`, `config/frps.toml`, and `README.md`. A matching `.sha256` file is published for every archive. For example, verify a Linux release using `sha256sum -c <archive-name>.sha256` from the folder containing both files.

### Automatic releases

- Every successful push to `main` creates an automatically numbered development prerelease (tag `ci-<run-number>`). All six platform builds must finish successfully before the release becomes public.
- Pushing a tag matching the version in `Cargo.toml`, such as `v0.1.0`, creates a stable release with automatically generated release notes after all checks pass.
- Pull requests run tests and static analysis without publishing releases.
- A manual run of **CI and Release** from `main` also produces a development prerelease.
- If any test, compilation, or archive validation fails, the release job does not run.

## Install

1. Install a recent stable Rust toolchain.
2. Run `cargo build --release`.
3. Copy `config/guard.toml` to a persistent location and adjust the parameters.
4. Run `./target/release/frp-connection-guard /path/to/guard.toml` on the frps host.
5. Add the following to the **existing** `frps.toml` (or use `config/frps.toml` as a snippet), then restart frps:

```toml
[[httpPlugins]]
name = "connection-guard"
addr = "127.0.0.1:9000"
path = "/handler"
ops = ["NewUserConn"]
```

**Important:** Keep the guard listener bound to loopback. Ensure the guard is running before frps accepts visitor traffic. If the plugin HTTP request fails, frps rejects the corresponding plugin operation; configure a process supervisor (for example, systemd) to restart the guard if it exits. Keep the SQLite database in a persistent directory writable by the guard process, with appropriate filesystem permissions.

## Configuration

See [config/guard.toml](config/guard.toml) for a complete example.

| TOML parameter | Default | Meaning |
|---|---:|---|
| `server.listen` | `127.0.0.1:9000` | RPC bind address |
| `server.path` | `/handler` | Must match frps plugin path |
| `server.max_body_bytes` | `16384` | Maximum RPC body in bytes |
| `protection.name_patterns` | `["*ssh*", "*rdp*"]` | Glob patterns matching frp proxy names |
| `protection.case_insensitive` | `true` | Case-insensitive name comparison |
| `protection.proxy_types` | `["tcp", "stcp", "https", "tcpmux"]` | Monitored proxy types (subject to frps event support) |
| `limits.short_window_secs` | `10` | Short accounting window in seconds |
| `limits.short_max_connections` | `6` | Connections allowed per IP in short window; next is banned |
| `limits.long_window_secs` | `60` | Longer accounting window in seconds |
| `limits.long_max_connections` | `20` | Connections allowed per IP in long window; next is banned |
| `limits.rapid_retry_gap_ms` | `1500` | Maximum separation for adjacent connections counted as rapid repeats |
| `limits.rapid_retry_window_secs` | `30` | Window retaining consecutive short-gap events |
| `limits.rapid_retry_max` | `4` | Rapid-repeat event count triggering a ban (roughly five tightly-spaced connections) |
| `limits.ban_duration_secs` | `3600` | Ban duration, in seconds |
| `limits.max_tracked_ips` | `100000` | Approximate maximum simultaneous per-IP state entries |
| `limits.idle_ttl_secs` | `600` | Cleanup idle-state age in seconds |
| `limits.cleanup_interval_secs` | `60` | Background cleanup period |
| `access.allow_cidrs` | `[]` | Trusted CIDR exceptions |
| `access.deny_cidrs` | `[]` | Static CIDR blacklist |
| `storage.sqlite_path` | `./frp-connection-guard.sqlite3` | Durable SQLite database path |

All dynamic counters are keyed by **IP globally**, not by IP-and-proxy, to stop one source from distributing attempts across SSH/RDP mapping names. A banned IP is refused on all `NewUserConn` mappings, including names outside the configured patterns. If a static deny range overlaps an allow range, the deny range wins.

### Recommended parameter selection

If a legitimate administrator frequently opens several RDP connections at once, increase `short_max_connections` and `rapid_retry_max` to avoid false positives. For stricter public SSH protections, decrease them gradually while checking authentication patterns. Long or aggressive bans can lock out legitimate users behind carrier-grade NAT or shared networks. Configure explicit narrow trusted CIDRs when appropriate.

## Test

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --release
python3 tests/attack_sim.py target/release/frp-connection-guard
```

The simulation opens actual loopback HTTP connections to the plugin and sends high-rate frps-style RPC requests. It validates rule matching, IPv4/IPv6 blocking, concurrent attacker bursts, an exemption list, and restart restoration. These tests exercise the plugin RPC boundary; they do not constitute an end-to-end frps/frpc or SSH/RDP authentication test.

## Operational notes

- The guard does not modify firewall rules. Blocking occurs at frps's plugin decision point.
- The frps ↔ guard traffic is intended for local loopback; requests have no plugin-authentication token.
- Requests with malformed remote IP addresses are rejected, including for unprotected proxies.
- At tracking capacity, previously unseen sources to protected mappings are rejected until idle entries are cleaned.
- SQLite writes happen when a ban is created; regular accepted connection checks use in-memory structures only.
- Preserve the SQLite file and accompanying journal files if relocating live state, or stop the guard before backup. Never share the database concurrently between independent guard processes.
- Configure the same listener path in the guard and in frps. A mismatch causes plugin requests to fail.
- Do not configure frps to use a Unix Socket URL in `httpPlugins.addr`: it is unsupported upstream.

## Reference

- [frp server plugin protocol](https://github.com/fatedier/frp/blob/dev/doc/server_plugin.md)
- [frps HTTP plugin implementation](https://github.com/fatedier/frp/blob/dev/pkg/plugin/server/http.go)

## License

MIT.
