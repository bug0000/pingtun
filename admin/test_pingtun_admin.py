import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess
import subprocess
import base64
import io
from types import SimpleNamespace
from email.message import Message

import pingtun_admin as admin


class AccountTests(unittest.TestCase):
    def test_transport_bounds_mobile_rules_and_wire_budget(self):
        defaults = dict(admin.TRANSPORT_DEFAULTS)
        self.assertEqual(admin.validate_transport(defaults, "android"), defaults)
        for field, value in (("max_pps", True), ("window", 17), ("mtu", 1408),
                             ("wire_mtu", 1300), ("lanes", 1.5), ("max_window", 129)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                admin.validate_transport(dict(defaults, **{field: value}))
        for change in ({"mtu": 1200}, {"id_mode": "rotate"}):
            with self.assertRaises(ValueError):
                admin.validate_transport(dict(defaults, **change), "android")
        self.assertEqual(admin.validate_transport(dict(defaults, mtu=1360, wire_mtu=1500))["mtu"], 1360)
        with self.assertRaises(ValueError):
            admin.validate_transport(dict(defaults, transport_key="untrusted"))

    def test_transport_defaults_are_private_and_do_not_touch_services(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(admin, "ROOT", Path(temporary)), \
                patch.object(admin, "command") as command:
            self.assertEqual(admin.transport_defaults(), admin.TRANSPORT_DEFAULTS)
            value = dict(admin.TRANSPORT_DEFAULTS, max_pps=500)
            admin.save_transport_defaults(value)
            self.assertEqual(admin.transport_defaults(), value)
            self.assertEqual((admin.ROOT / "transport.json").stat().st_mode & 0o777, 0o600)
            command.assert_not_called()

    def test_transport_update_keeps_profiles_in_sync_and_rolls_back_restart_failure(self):
        for active, fail in ((True, False), (False, False), (True, True)):
            with self.subTest(active=active, fail=fail), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(admin, "ROOT", Path(temporary)):
                path = admin.ROOT / "accounts" / "a0001"
                path.mkdir(parents=True)
                (path / "account.json").write_text(json.dumps({"kind": "android"}))
                server = {"role": "server", "private_key": "server-secret"}
                client = {"role": "client", "private_key": "client-secret", "socket_mode": "ping"}
                for config in (server, client):
                    admin.apply_transport(config, admin.TRANSPORT_DEFAULTS)
                original = {"server.json": json.dumps(server), "client.json": json.dumps(client),
                            "profile.pingtun.json": json.dumps({"config": client, "name": "Phone"})}
                for name, data in original.items():
                    (path / name).write_text(data)
                calls = []
                def command(*args):
                    calls.append(args)
                    if fail and args[:2] == ("systemctl", "restart") and sum(c[:2] == args[:2] for c in calls) == 1:
                        raise subprocess.CalledProcessError(1, args)
                    return ""
                with patch.object(admin, "command", side_effect=command), \
                        patch.object(admin, "service_state", return_value="active" if active else "inactive"):
                    value = dict(admin.TRANSPORT_DEFAULTS, max_pps=400, wire_mtu=1500)
                    if fail:
                        with self.assertRaises(subprocess.CalledProcessError):
                            admin.update_transport("a0001", value)
                        self.assertEqual({n: (path / n).read_text() for n in original}, original)
                    else:
                        result = admin.update_transport("a0001", value)
                        self.assertEqual(result["restarted"], active)
                        self.assertEqual(admin.account_transport("a0001"), value)
                        updated = json.loads((path / "client.json").read_text())
                        self.assertEqual(updated["private_key"], "client-secret")
                        self.assertEqual(json.loads((path / "profile.pingtun.json").read_text())["config"], updated)
                        self.assertEqual((path / "client.json").stat().st_mode & 0o777, 0o600)
                    restarts = [c for c in calls if c[:2] == ("systemctl", "restart")]
                    self.assertEqual(len(restarts), 2 if fail else int(active))
                    checks = [c for c in calls if c[1] == "check"]
                    self.assertEqual(len(checks), 2)

    def test_transport_validation_failure_does_not_change_files(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(admin, "ROOT", Path(temporary)):
            path = admin.ROOT / "accounts" / "a0001"
            path.mkdir(parents=True)
            (path / "account.json").write_text('{"kind":"android"}')
            config = {"private_key": "secret"}
            admin.apply_transport(config, admin.TRANSPORT_DEFAULTS)
            original = json.dumps(config)
            for name in ("server.json", "client.json"):
                (path / name).write_text(original)
            (path / "profile.pingtun.json").write_text(json.dumps({"config": config}))
            with patch.object(admin, "service_state", return_value="active"), \
                    patch.object(admin, "command", side_effect=subprocess.CalledProcessError(1, "check")):
                with self.assertRaises(subprocess.CalledProcessError):
                    admin.update_transport("a0001", dict(admin.TRANSPORT_DEFAULTS, max_pps=500))
            self.assertEqual((path / "server.json").read_text(), original)

    def test_mobile_name_limit_uses_utf8_bytes(self):
        self.assertEqual(admin.validate_name("Я" * 32), "Я" * 32)
        with self.assertRaises(ValueError):
            admin.validate_name("Я" * 33)
        with self.assertRaises(ValueError):
            admin.validate_name("Name\u0085")

    def test_http_transport_requires_authentication_and_exact_origin(self):
        credentials = admin.build_credentials("owner", "long-private-password")
        def handler(origin="https://admin.example.com", authorization=True, payload=None):
            h = object.__new__(admin.Handler)
            h.headers = Message()
            h.headers["Content-Type"] = "application/json"
            h.headers["Origin"] = origin
            h.headers["X-Pingtun-Admin"] = "1"
            if authorization:
                h.headers["Authorization"] = "Basic " + base64.b64encode(b"owner:long-private-password").decode()
            data = json.dumps(admin.TRANSPORT_DEFAULTS if payload is None else payload).encode()
            h.headers["Content-Length"] = str(len(data))
            h.path = "/api/transport"
            h.rfile = io.BytesIO(data)
            h.wfile = io.BytesIO()
            h.client_address = ("127.0.0.1", 1)
            h.server = SimpleNamespace(credentials=credentials, public_origin="https://admin.example.com")
            h.send_response = lambda status: setattr(h, "status", status)
            h.send_header = lambda *args: None
            h.end_headers = lambda: None
            return h
        with patch.object(admin, "FAILURES", {}), patch.object(admin, "save_transport_defaults", return_value=admin.TRANSPORT_DEFAULTS) as save:
            h = handler(authorization=False)
            h.do_POST()
            self.assertEqual(h.status, 401)
            save.assert_not_called()
            h = handler(origin="https://evil.example.com")
            h.do_POST()
            self.assertEqual(h.status, 403)
            save.assert_not_called()
            h = handler(payload=[])
            h.do_POST()
            self.assertEqual(h.status, 400)
            save.assert_not_called()
            h = handler()
            h.do_POST()
            self.assertEqual(h.status, 200)
            save.assert_called_once_with(admin.TRANSPORT_DEFAULTS)

    def test_admin_credentials_are_salted_and_verifiable(self):
        one = admin.build_credentials("owner", "long-private-password")
        two = admin.build_credentials("owner", "long-private-password")
        self.assertNotEqual(one["hash"], two["hash"])
        self.assertTrue(admin.verify_credentials(one, "owner", "long-private-password"))
        self.assertFalse(admin.verify_credentials(one, "owner", "wrong-password"))
        self.assertFalse(admin.verify_credentials(one, "other", "long-private-password"))
        self.assertNotIn("long-private-password", json.dumps(one))

    def test_admin_credentials_are_saved_private(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(admin, "ROOT", Path(temporary)):
            credentials = admin.build_credentials("owner", "long-private-password")
            admin.save_credentials(credentials)
            path = Path(temporary) / "credentials.json"
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(admin.load_credentials(), credentials)

    def test_login_throttle_resets_after_success(self):
        with patch.object(admin, "FAILURES", {}):
            self.assertFalse(admin.rate_limited("192.0.2.2"))
            self.assertEqual(admin.FAILURES, {})
            for _ in range(5):
                admin.record_failure("192.0.2.1")
            self.assertTrue(admin.rate_limited("192.0.2.1"))
            self.assertFalse(admin.rate_limited("192.0.2.2"))
            admin.clear_failures("192.0.2.1")
            self.assertFalse(admin.rate_limited("192.0.2.1"))

    def test_addresses_are_distinct_and_in_pool(self):
        self.assertEqual(admin.addresses(1), ("10.253.0.5", "10.253.0.6"))
        self.assertEqual(admin.addresses(4095), ("10.253.63.253", "10.253.63.254"))
        with self.assertRaises(ValueError):
            admin.addresses(4096)

    def test_create_block_and_delete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            units = Path(temporary) / "units"
            root.mkdir()
            units.mkdir()
            (root / "accounts").mkdir()
            calls = []

            def fake_command(*args):
                calls.append(args)
                if args[0] == "/usr/local/bin/pingtun" and args[1] == "init":
                    generated = Path(args[-1])
                    generated.mkdir()
                    base = {"role": "server", "interface": "pingtun0", "allowed_ips": ["10.203.0.2/32"]}
                    (generated / "server.json").write_text(json.dumps(base))
                    base["role"] = "client"
                    (generated / "client.json").write_text(json.dumps(base))
                return ""

            with patch.object(admin, "ROOT", root), patch.object(admin, "UNITS", units), patch.object(admin, "command", side_effect=fake_command), patch.object(admin, "route_conflict", return_value=False):
                account = admin.create("Phone", "android", "8.8.8.8", "ens3")
                self.assertEqual(account["id"], "a0001")
                self.assertEqual(account["client_address"], "10.253.0.6/30")
                path = root / "accounts" / "a0001"
                server = json.loads((path / "server.json").read_text())
                profile = json.loads((path / "profile.pingtun.json").read_text())
                self.assertEqual(server["allowed_ips"], ["10.253.0.6/32"])
                self.assertEqual(profile["config"]["socket_mode"], "ping")
                self.assertEqual(profile["config"]["adaptive"], server["adaptive"])
                rules = (path / "network.nft").read_text()
                self.assertIn('chain input {', rules)
                self.assertIn('iifname "pta0001" drop', rules)
                self.assertEqual((path / "client.json").stat().st_mode & 0o777, 0o600)
                self.assertIn(("systemctl", "enable", "--now", "pingtun-admin@a0001.service"), calls)
                admin.set_blocked("a0001", True)
                self.assertIn(("systemctl", "disable", "--now", "pingtun-admin@a0001.service"), calls)
                admin.delete("a0001")
                self.assertFalse(path.exists())

    def test_rejects_invalid_names_and_private_server(self):
        with self.assertRaises(ValueError):
            admin.validate_name("\n")
        with self.assertRaises(ValueError):
            admin.create("Valid", "linux", "10.0.0.1", "ens3")

    def test_reused_id_does_not_show_previous_accounts_traffic(self):
        def journal_entry(timestamp, stats):
            return json.dumps({"__REALTIME_TIMESTAMP": str(timestamp * 1_000_000),
                               "MESSAGE": json.dumps(stats)})

        old = journal_entry(100, {"rx_bytes": 1000, "tx_bytes": 2000})
        new = journal_entry(200, {"rx_bytes": 20, "tx_bytes": 30})
        with patch.object(admin.subprocess, "run", return_value=CompletedProcess([], 0, old + "\n")):
            self.assertEqual(admin.latest_stats("pingtun-admin@a0001.service", 150), {})
        with patch.object(admin.subprocess, "run", return_value=CompletedProcess([], 0, old + "\n" + new + "\n")):
            self.assertEqual(admin.latest_stats("pingtun-admin@a0001.service", 150)["rx_bytes"], 20)

    def test_legacy_wire_stats_are_labeled_separately(self):
        row = json.dumps({"__REALTIME_TIMESTAMP": "200000000", "MESSAGE":
                          json.dumps({"wire_received_bytes": 123, "wire_sent_bytes": 456})})
        with patch.object(admin.subprocess, "run", return_value=CompletedProcess([], 0, row)):
            stats = admin.latest_stats("pingtun230.service", 0)
        self.assertEqual(stats["source"], "wire")
        self.assertEqual((stats["rx_bytes"], stats["tx_bytes"]), (123, 456))

    def test_route_on_similarly_named_interface_is_still_a_conflict(self):
        routes = '[{"dst":"10.253.0.4/30","dev":"pta9999"}]'
        with patch.object(admin, "command", return_value=routes):
            self.assertTrue(admin.route_conflict(admin.ipaddress.ip_network("10.253.0.4/30")))

    def test_legacy_account_is_listed_and_can_be_blocked_without_deleting_files(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(admin, "ROOT", Path(temporary)):
            registry = [{"id": "legacy-pingtun230", "name": "Old link", "kind": "linux",
                         "client_address": "10.254.234.2/30"}]
            (Path(temporary) / "legacy.json").write_text(json.dumps(registry))
            (Path(temporary) / "accounts").mkdir()
            calls = []
            with patch.object(admin, "command", side_effect=lambda *args: calls.append(args) or ""), \
                    patch.object(admin, "service_state", return_value="active"), \
                    patch.object(admin, "latest_stats", return_value={"rx_bytes": 42}):
                accounts = admin.list_accounts()
                self.assertEqual(accounts[0]["source"], "legacy")
                self.assertEqual(accounts[0]["stats"]["rx_bytes"], 42)
                admin.set_blocked("legacy-pingtun230", True)
                self.assertIn(("systemctl", "disable", "--now", "pingtun230.service"), calls)
                with self.assertRaises(FileNotFoundError):
                    admin.set_blocked("legacy-pingtun999", True)

    def test_legacy_registry_rejects_admin_service(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(admin, "ROOT", Path(temporary)):
            registry = [{"id": "legacy-pingtun-admin", "name": "Invalid", "kind": "linux",
                         "client_address": "10.254.234.2/30"}]
            (Path(temporary) / "legacy.json").write_text(json.dumps(registry))
            with self.assertRaises(ValueError):
                admin.legacy_accounts()


if __name__ == "__main__":
    unittest.main()
