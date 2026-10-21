import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

import pingtun_admin as admin


class AccountTests(unittest.TestCase):
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
