#!/usr/bin/env python3
"""Loopback RPC attack simulation for the frps guard executable."""
import concurrent.futures
import http.client
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time


def get_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def call(port, ip, proxy="office-ssh", connection_port=35000):
    body = json.dumps({
        "version": "0.1.0",
        "op": "NewUserConn",
        "content": {
            "proxy_name": proxy,
            "proxy_type": "tcp",
            "remote_addr": f"[{ip}]:{connection_port}" if ":" in ip else f"{ip}:{connection_port}",
        },
    })
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("POST", "/handler?version=0.1.0&op=NewUserConn",
                     body=body, headers={"Content-Type": "application/json"})
        result = conn.getresponse()
        payload = json.loads(result.read())
        assert result.status == 200, (result.status, payload)
        return payload["reject"]
    finally:
        conn.close()


def launch(binary, config, port):
    process = subprocess.Popen(
        [str(binary), str(config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError(f"guard quit early: {process.stderr.read().decode()}")
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
            conn.request("GET", "/healthz")
            response = conn.getresponse()
            data = response.read()
            conn.close()
            if response.status == 200 and data == b"ok":
                return process
        except OSError:
            time.sleep(0.05)
    process.kill()
    raise RuntimeError("guard did not open its health endpoint")


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    process.stderr.close()


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: python3 tests/attack_sim.py PATH_TO_BINARY")
    binary = pathlib.Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory() as directory:
        temp = pathlib.Path(directory)
        port = get_port()
        config = temp / "guard.toml"
        database = temp / "bans.db"
        config.write_text(
            f'''[server]
listen = "127.0.0.1:{port}"
path = "/handler"

[protection]
name_patterns = ["*ssh*", "*rdp*"]

[limits]
short_window_secs = 10
short_max_connections = 5
long_window_secs = 60
long_max_connections = 100
rapid_retry_gap_ms = 5000
rapid_retry_window_secs = 30
rapid_retry_max = 3
ban_duration_secs = 3600
max_tracked_ips = 10000

[access]
allow_cidrs = ["192.0.2.0/24"]
deny_cidrs = ["198.51.100.0/24"]

[storage]
sqlite_path = "{database.as_posix()}"
''',
            encoding="utf-8",
        )
        server = launch(binary, config, port)
        try:
            assert not call(port, "203.0.113.20", "web-public")
            for index in range(3):
                assert not call(port, "203.0.113.20", connection_port=4000 + index)
            assert call(port, "203.0.113.20", connection_port=4003)
            assert call(port, "203.0.113.20", "web-public")
            assert call(port, "::ffff:203.0.113.20", "office-rdp")
            for index in range(3):
                assert not call(port, "2001:db8::20", connection_port=5000 + index)
            assert call(port, "2001:db8::20", connection_port=5003)
            assert call(port, "198.51.100.4", "web-public")
            for _ in range(20):
                assert not call(port, "192.0.2.5")
            # Concurrent malicious bursts from 30 different addresses.
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                replies = list(pool.map(
                    lambda item: call(port, f"203.0.113.{50 + item // 4}", connection_port=6000 + item),
                    range(120),
                ))
            assert sum(replies) >= 30, "concurrent attackers should trigger bans"
            print("PASS: malicious IPv4/IPv6 attempts rejected, whitelists and CIDRs applied")
        finally:
            stop(server)

        # A fresh process must load blacklisted IPs from SQLite before serving.
        server = launch(binary, config, port)
        try:
            assert call(port, "203.0.113.20", "web-public")
            assert call(port, "2001:db8::20", "web-public")
            assert not call(port, "203.0.113.250", "web-public")
            print("PASS: blacklist persisted after process restart")
        finally:
            stop(server)


if __name__ == "__main__":
    main()
