#!/usr/bin/env python3
"""Run only in a disposable user/network namespace; never starts host services."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

import pingtun_admin as admin


def verify(binary):
    binary = str(Path(binary).resolve())
    with tempfile.TemporaryDirectory(prefix="pingtun-admin-check-") as temporary:
        root = Path(temporary)
        (root / "accounts").mkdir()
        units = root / "units"
        units.mkdir()
        calls = []

        def command(*args):
            if args[0] == "systemctl":
                calls.append(args)
                return ""
            if args[0] == "/usr/local/bin/pingtun":
                args = (binary, *args[1:])
            return subprocess.run(args, check=True, text=True, capture_output=True, timeout=30).stdout

        with patch.object(admin, "ROOT", root), patch.object(admin, "UNITS", units), \
                patch.object(admin, "command", side_effect=command), \
                patch.object(admin, "service_state", return_value="inactive"):
            for kind in ("android", "linux"):
                account = admin.create("Test " + kind, kind, "8.8.8.8", "eth0")
                identifier = account["id"]
                value = dict(admin.TRANSPORT_DEFAULTS, wire_mtu=1500, mtu=1360,
                             max_pps=500, lanes=4, window=8, max_window=64)
                if kind == "linux":
                    value["id_mode"] = "rotate"
                admin.update_transport(identifier, value)
                path = admin.account_dir(identifier)
                server = json.loads((path / "server.json").read_text())
                client = json.loads((path / "client.json").read_text())
                assert server["adaptive"] == client["adaptive"]
                assert admin.account_transport(identifier) == value
                if kind == "android":
                    profile = json.loads((path / "profile.pingtun.json").read_text())
                    assert profile["config"] == client
                for name in ("server.json", "client.json"):
                    command(binary, "check", "--config", str(path / name))
            assert not any(call[1] == "restart" for call in calls)
    print("Admin integration passed: real config generation/checks, nft syntax, profile synchronization")


if __name__ == "__main__":
    verify(sys.argv[1])
