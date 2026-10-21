import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pingtun_admin as admin


class AccountTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
