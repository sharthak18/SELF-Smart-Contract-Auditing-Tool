"""Test that scans stay offline: no intelligence module is imported during a scan."""

import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class OfflineGuardTests(unittest.TestCase):
    def test_intelligence_modules_not_imported_during_scan(self):
        """Scanning must never pull in the intelligence (network) modules."""
        repo_root = Path(__file__).resolve().parent.parent
        script = """
import json
import sys
import tempfile
from pathlib import Path
from self_tool.core.scanner import discover_files
from self_tool.core.detector_engine import DetectorEngine
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    (root / 'A.sol').write_text('pragma solidity ^0.8.0;\\ncontract A {}\\n')
    files, _ = discover_files(str(root))
    DetectorEngine().run(files)
print(json.dumps(sorted(name for name in sys.modules if name.startswith('self_tool.intelligence'))))
"""
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=str(repo_root),
            text=True, capture_output=True, check=True,
        )
        self.assertEqual(result.stdout.strip(), "[]")

    def test_scanner_blocks_network_at_socket_layer(self):
        """Patching socket.socket prevents any unintended network call from a scan."""
        class _Blocked(socket.socket):
            def __init__(self, *args, **kwargs):
                raise RuntimeError("offline guard: socket blocked")
            def __getattribute__(self, name):
                raise RuntimeError("offline guard: socket blocked")

        from self_tool.core.scanner import discover_files

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "A.sol").write_text(
                "pragma solidity ^0.8.0;\ncontract A {}\n", encoding="utf-8"
            )
            with patch("socket.socket", _Blocked):
                files, _ = discover_files(str(root))
            self.assertGreaterEqual(len(files), 1)


if __name__ == "__main__":
    unittest.main()
