#!/usr/bin/env python3
"""Local account console for one-peer-per-instance pingtun servers."""

import argparse
import base64
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


ROOT = Path("/etc/pingtun/admin")
UNITS = Path("/etc/systemd/system")
POOL = ipaddress.ip_network("10.253.0.0/16")
ID_PATTERN = re.compile(r"a[0-9]{4}\Z")
LEGACY_ID_PATTERN = re.compile(r"legacy-(pingtun(?:-[a-z0-9]+|[0-9]+))\Z")
NAME_PATTERN = re.compile(r"[^\x00-\x1f\x7f]{1,64}\Z")
LOGIN_PATTERN = re.compile(r"[A-Za-z0-9_.-]{3,32}\Z")
LOCK = threading.RLock()
AUTH_LOCK = threading.RLock()
FAILURES = {}
SCRYPT_N = 1 << 14


def command(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def write_private(path, data):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def validate_login(login):
    if not isinstance(login, str) or not LOGIN_PATTERN.fullmatch(login):
        raise ValueError("login must be 3 to 32 Latin letters, digits, dots, dashes or underscores")
    return login


def validate_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in password):
        raise ValueError("password must contain 12 to 128 printable characters")
    return password


def password_hash(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=8, p=1,
                          dklen=32, maxmem=64 * 1024 * 1024)


def build_credentials(login, password):
    validate_login(login)
    validate_password(password)
    salt = secrets.token_bytes(32)
    return {"login": login, "salt": base64.b64encode(salt).decode(),
            "hash": base64.b64encode(password_hash(password, salt)).decode()}


def verify_credentials(credentials, login, password):
    try:
        salt = base64.b64decode(credentials["salt"], validate=True)
        expected = base64.b64decode(credentials["hash"], validate=True)
        actual = password_hash(password, salt)
        return hmac.compare_digest(login, credentials["login"]) and hmac.compare_digest(actual, expected)
    except (KeyError, ValueError, TypeError):
        return False


def save_credentials(credentials):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=ROOT, prefix=".credentials-",
                                     delete=False) as stream:
        temporary = Path(stream.name)
        os.fchmod(stream.fileno(), 0o600)
        json.dump(credentials, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, ROOT / "credentials.json")
    finally:
        temporary.unlink(missing_ok=True)


def load_credentials():
    path = ROOT / "credentials.json"
    if not path.exists():
        legacy = ROOT / "password"
        if not legacy.exists():
            raise RuntimeError("set administrator credentials before starting the service")
        save_credentials(build_credentials("admin", legacy.read_text().strip()))
        legacy.unlink()
    return json.loads(path.read_text())


def failure_key(handler):
    # Only the loopback reverse proxy can reach the HTTP listener.
    return handler.headers.get("X-Real-IP", "") or handler.client_address[0]


def rate_limited(key):
    with AUTH_LOCK:
        now = time.monotonic()
        recent = [t for t in FAILURES.get(key, []) if now - t < 600]
        if recent:
            FAILURES[key] = recent
        else:
            FAILURES.pop(key, None)
        return len(recent) >= 5


def record_failure(key):
    with AUTH_LOCK:
        now = time.monotonic()
        if len(FAILURES) >= 4096 and key not in FAILURES:
            for address, attempts in list(FAILURES.items()):
                if now - attempts[-1] >= 600:
                    del FAILURES[address]
            if len(FAILURES) >= 4096:
                FAILURES.pop(next(iter(FAILURES)))
        FAILURES.setdefault(key, []).append(now)


def clear_failures(key):
    with AUTH_LOCK:
        FAILURES.pop(key, None)


def account_dir(identifier):
    if not ID_PATTERN.fullmatch(identifier):
        raise ValueError("invalid account ID")
    return ROOT / "accounts" / identifier


def unit(identifier):
    account_dir(identifier)
    return f"pingtun-admin@{identifier}.service"


def legacy_unit(identifier):
    match = LEGACY_ID_PATTERN.fullmatch(identifier)
    if not match or match.group(1) in {"pingtun-admin", "pingtun-probe", "pingtun-experiment"}:
        raise ValueError("invalid legacy account ID")
    return f"{match.group(1)}.service"


def legacy_accounts():
    path = ROOT / "legacy.json"
    if not path.exists():
        return []
    entries = json.loads(path.read_text())
    if not isinstance(entries, list):
        raise ValueError("legacy account registry must be a list")
    accounts = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid legacy account entry")
        identifier = entry["id"]
        legacy_unit(identifier)
        if identifier in seen:
            raise ValueError("duplicate legacy account ID")
        seen.add(identifier)
        address = ipaddress.ip_interface(entry["client_address"])
        if address.version != 4 or address.network.prefixlen != 30:
            raise ValueError("legacy client address must be IPv4 /30")
        kind = entry["kind"]
        if kind not in ("android", "linux"):
            raise ValueError("invalid legacy client type")
        accounts.append({"id": identifier, "name": validate_name(entry["name"]),
                         "kind": kind, "client_address": str(address), "source": "legacy"})
    return accounts


def addresses(number):
    if not 1 <= number < 4096:
        raise ValueError("address pool exhausted")
    network = ipaddress.ip_network((int(POOL.network_address) + number * 4, 30))
    return str(network.network_address + 1), str(network.network_address + 2)


def next_id():
    for number in range(1, 4096):
        identifier = f"a{number:04d}"
        if not account_dir(identifier).exists():
            return identifier, number
    raise ValueError("address pool exhausted")


def route_conflict(network):
    """Avoid assigning an address already routed outside this admin pool."""
    try:
        routes = json.loads(command("/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all"))
    except (ValueError, subprocess.CalledProcessError):
        raise ValueError("cannot inspect IPv4 routes")
    for route in routes:
        destination = route.get("dst", "default")
        if destination == "default":
            continue
        try:
            prefix = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if prefix.overlaps(network):
            return True
    return False


def validate_name(name):
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name) or not name.strip():
        raise ValueError("name must contain 1 to 64 printable characters")
    return name.strip()


def create(name, kind, server_ip, external_if):
    name = validate_name(name)
    if kind not in ("android", "linux"):
        raise ValueError("client type must be android or linux")
    public_ip = ipaddress.ip_address(server_ip)
    if public_ip.version != 4 or not public_ip.is_global:
        raise ValueError("server must have a public IPv4 address")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", external_if):
        raise ValueError("invalid external interface")
    with LOCK:
        identifier, number = next_id()
        server_addr, client_addr = addresses(number)
        if route_conflict(ipaddress.ip_network(f"{server_addr}/30", strict=False)):
            raise ValueError("allocated subnet conflicts with an existing route")
        path = account_dir(identifier)
        path.mkdir(mode=0o700)
        dropin = UNITS / f"pingtun-admin@{identifier}.service.d"
        try:
            with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
                generated = Path(temporary) / "pair"
                command("/usr/local/bin/pingtun", "init", "--server", server_ip, "--dir", str(generated))
                server = json.loads((generated / "server.json").read_text())
                client = json.loads((generated / "client.json").read_text())
            interface = f"pt{identifier}"
            server["interface"] = interface
            server["allowed_ips"] = [f"{client_addr}/32"]
            client["interface"] = interface
            if kind == "android":
                client["socket_mode"] = "ping"
            profile = {"version": 1, "name": name, "address": f"{client_addr}/30",
                       "dns": ["1.1.1.1"], "config": client}
            metadata = {"id": identifier, "name": name, "kind": kind,
                        "server_address": f"{server_addr}/30", "client_address": f"{client_addr}/30",
                        "interface": interface, "created_unix": time.time()}
            write_private(path / "server.json", json.dumps(server, indent=2) + "\n")
            write_private(path / "client.json", json.dumps(client, indent=2) + "\n")
            if kind == "android":
                write_private(path / "profile.pingtun.json", json.dumps(profile, indent=2) + "\n")
            write_private(path / "account.json", json.dumps(metadata, indent=2) + "\n")
            table = f"pingtun_{identifier}"
            rules = f'''table ip {table} {{
 chain echo_guard {{
  type filter hook output priority -5; policy accept;
  icmp type echo-reply @th,64,48 0x5054554e0201 drop
 }}
 chain forward {{
  type filter hook forward priority 0; policy accept;
  iifname "{interface}" ip saddr != {client_addr} drop
  iifname "{interface}" oifname "{external_if}" accept
  iifname "{interface}" drop
  oifname "{interface}" ct state established,related accept
  oifname "{interface}" drop
 }}
 chain nat {{
  type nat hook postrouting priority srcnat; policy accept;
  ip saddr {client_addr} oifname "{external_if}" masquerade
 }}
}}
'''
            write_private(path / "network.nft", rules)
            dropin.mkdir(mode=0o755)
            (dropin / "address.conf").write_text(
                f"[Service]\nExecStartPost=/usr/local/libexec/pingtun-link-up {interface} {server_addr}/30\n"
            )
            command("/usr/sbin/nft", "-c", "-f", str(path / "network.nft"))
            command("/usr/local/bin/pingtun", "check", "--config", str(path / "server.json"))
            command("systemctl", "daemon-reload")
            command("systemctl", "enable", "--now", unit(identifier))
            return metadata
        except BaseException:
            try:
                command("systemctl", "disable", "--now", unit(identifier))
            except (OSError, subprocess.CalledProcessError):
                pass
            shutil.rmtree(path, ignore_errors=True)
            shutil.rmtree(dropin, ignore_errors=True)
            try:
                command("systemctl", "daemon-reload")
            except (OSError, subprocess.CalledProcessError):
                pass
            raise


def service_state(service):
    result = subprocess.run(("systemctl", "is-active", service), text=True, capture_output=True)
    return result.stdout.strip() or "unknown"


def latest_stats(service, created_unix):
    result = subprocess.run(("journalctl", "-u", service, "-o", "json", "-n", "200", "--no-pager"),
                            text=True, capture_output=True)
    if result.returncode:
        return {}
    for line in reversed(result.stdout.splitlines()):
        try:
            record = json.loads(line)
            value = json.loads(record["MESSAGE"])
            timestamp = int(record["__REALTIME_TIMESTAMP"]) / 1_000_000
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
        if timestamp < created_unix or not isinstance(value, dict):
            continue
        if isinstance(value.get("rx_bytes"), int) and isinstance(value.get("tx_bytes"), int):
            stats = {key: value[key] for key in ("rx_bytes", "tx_bytes", "last_handshake_time_sec")
                     if isinstance(value.get(key), int)}
            stats.update(now_unix=int(timestamp), source="payload")
            return stats
        if (isinstance(value.get("wire_received_bytes"), int)
                and isinstance(value.get("wire_sent_bytes"), int)):
            return {"rx_bytes": value["wire_received_bytes"], "tx_bytes": value["wire_sent_bytes"],
                    "now_unix": int(timestamp), "source": "wire"}
    return {}


def list_accounts():
    results = []
    for path in sorted((ROOT / "accounts").glob("a[0-9][0-9][0-9][0-9]")):
        try:
            metadata = json.loads((path / "account.json").read_text())
            identifier = metadata["id"]
            if account_dir(identifier) != path:
                continue
            metadata["source"] = "managed"
            metadata["state"] = service_state(unit(identifier))
            metadata["stats"] = latest_stats(unit(identifier), metadata["created_unix"])
            results.append(metadata)
        except (OSError, ValueError, KeyError):
            continue
    for metadata in legacy_accounts():
        service = legacy_unit(metadata["id"])
        metadata["state"] = service_state(service)
        metadata["stats"] = latest_stats(service, 0)
        results.append(metadata)
    return results


def set_blocked(identifier, blocked):
    with LOCK:
        if ID_PATTERN.fullmatch(identifier):
            if not (account_dir(identifier) / "account.json").is_file():
                raise FileNotFoundError("account not found")
            service = unit(identifier)
        else:
            service = next((legacy_unit(entry["id"]) for entry in legacy_accounts()
                            if entry["id"] == identifier), None)
            if service is None:
                raise FileNotFoundError("account not found")
        command("systemctl", "disable" if blocked else "enable", "--now", service)


def delete(identifier):
    path = account_dir(identifier)
    with LOCK:
        if not (path / "account.json").is_file():
            raise FileNotFoundError("account not found")
        command("systemctl", "disable", "--now", unit(identifier))
        shutil.rmtree(path)
        shutil.rmtree(UNITS / f"pingtun-admin@{identifier}.service.d")
        command("systemctl", "daemon-reload")


class Handler(BaseHTTPRequestHandler):
    server_version = "pingtun-admin"

    def log_message(self, format, *args):
        # HTTP paths and authorization values never enter a journal.
        pass

    def respond(self, status, body=b"", content_type="application/json", attachment=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.end_headers()
        self.wfile.write(body)

    def authenticated(self):
        header = self.headers.get("Authorization", "")
        if len(header) > 512 or not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
            user, password = decoded.split(":", 1)
        except (ValueError, UnicodeError):
            return False
        with AUTH_LOCK:
            return verify_credentials(self.server.credentials, user, password)

    def guard(self, mutation=False):
        key = failure_key(self)
        if rate_limited(key):
            self.respond(429, b'{"error":"too many login attempts; try again later"}')
            return False
        if not self.authenticated():
            record_failure(key)
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="pingtun admin", charset="UTF-8"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        clear_failures(key)
        if mutation:
            origin = self.headers.get("Origin", "")
            if (self.headers.get("X-Pingtun-Admin") != "1" or
                    self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json" or
                    origin != self.server.public_origin):
                self.respond(403, b'{"error":"request rejected"}')
                return False
        return True

    def do_GET(self):
        if not self.guard():
            return
        path = urlsplit(self.path).path
        if path == "/":
            self.respond(200, (Path(__file__).parent / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif path == "/app.js":
            self.respond(200, (Path(__file__).parent / "app.js").read_bytes(), "text/javascript; charset=utf-8")
        elif path == "/style.css":
            self.respond(200, (Path(__file__).parent / "style.css").read_bytes(), "text/css; charset=utf-8")
        elif path == "/api/accounts":
            self.respond(200, json.dumps(list_accounts()).encode())
        elif path == "/api/admin":
            with AUTH_LOCK:
                self.respond(200, json.dumps({"login": self.server.credentials["login"]}).encode())
        elif re.fullmatch(r"/api/accounts/a[0-9]{4}/download", path):
            identifier = path.split("/")[3]
            account = account_dir(identifier)
            try:
                kind = json.loads((account / "account.json").read_text())["kind"]
                filename = "profile.pingtun.json" if kind == "android" else "client.json"
                self.respond(200, (account / filename).read_bytes(), "application/json", f"{identifier}-{filename}")
            except (OSError, ValueError, KeyError):
                self.respond(404, b'{"error":"account not found"}')
        else:
            self.respond(404, b'{"error":"not found"}')

    def do_POST(self):
        if not self.guard(mutation=True):
            return
        try:
            size = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self.respond(400, b'{"error":"invalid request size"}')
            return
        if not 0 < size <= 4096:
            self.respond(400, b'{"error":"invalid request size"}')
            return
        try:
            payload = json.loads(self.rfile.read(size))
            path = urlsplit(self.path).path
            if path == "/api/accounts":
                result = create(payload["name"], payload["kind"], self.server.server_ip, self.server.external_if)
                self.respond(201, json.dumps(result).encode())
            elif path == "/api/admin":
                with AUTH_LOCK:
                    if not verify_credentials(self.server.credentials, self.server.credentials["login"], payload["current_password"]):
                        self.respond(403, b'{"error":"current password is incorrect"}')
                        return
                    credentials = build_credentials(payload["login"], payload["password"])
                    save_credentials(credentials)
                    self.server.credentials = credentials
                self.respond(200, b'{"ok":true}')
            elif re.fullmatch(r"/api/accounts/(?:a[0-9]{4}|legacy-pingtun(?:-[a-z0-9]+|[0-9]+))/(block|unblock|delete)", path):
                identifier, action = path.split("/")[3:5]
                if action == "delete":
                    if not ID_PATTERN.fullmatch(identifier):
                        self.respond(403, b'{"error":"legacy accounts cannot be deleted here"}')
                        return
                    delete(identifier)
                else:
                    set_blocked(identifier, action == "block")
                self.respond(200, b'{"ok":true}')
            else:
                self.respond(404, b'{"error":"not found"}')
        except (KeyError, ValueError, TypeError, FileNotFoundError) as exc:
            self.respond(400, json.dumps({"error": str(exc)}).encode())
        except (OSError, subprocess.CalledProcessError):
            self.respond(500, b'{"error":"server operation failed; check service journal"}')


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "set-credentials":
        setup = argparse.ArgumentParser()
        setup.add_argument("--login", required=True)
        options = setup.parse_args(sys.argv[2:])
        password = getpass.getpass("New administrator password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            setup.error("passwords do not match")
        ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        save_credentials(build_credentials(options.login, password))
        (ROOT / "password").unlink(missing_ok=True)
        print("Administrator credentials updated. Restart pingtun-admin.service if it is running.")
        return
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--external-if", required=True)
    parser.add_argument("--listen", default="127.0.0.1:8787")
    parser.add_argument("--public-origin", default="http://127.0.0.1:8787")
    args = parser.parse_args()
    if not args.listen.startswith("127.0.0.1:"):
        parser.error("admin console must listen on 127.0.0.1")
    public_ip = ipaddress.ip_address(args.server_ip)
    if public_ip.version != 4 or not public_ip.is_global:
        parser.error("server-ip must be a public IPv4 address")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", args.external_if):
        parser.error("invalid external interface")
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    (ROOT / "accounts").mkdir(mode=0o700, exist_ok=True)
    if not args.public_origin.startswith(("https://", "http://127.0.0.1:")):
        parser.error("public origin must use HTTPS")
    credentials = load_credentials()
    host, port = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), Handler)
    server.credentials = credentials
    server.server_ip = args.server_ip
    server.external_if = args.external_if
    server.public_origin = args.public_origin
    server.serve_forever()


if __name__ == "__main__":
    main()
