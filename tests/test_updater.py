"""Tests for the metadata-only advisory updater (Phase 5)."""

import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from self_tool.core.fingerprints import canonical_json, sha256_hex
from self_tool.intelligence.cache import Cache
from self_tool.intelligence.fetcher import FetchError, fetch_https
from self_tool.intelligence.install import install_snapshot
from self_tool.intelligence.manifest import ManifestError, verify_manifest
from self_tool.intelligence.validator import validate_record, validate_record_list


def _good_manifest(*, sources=("owasp-scs",)):
    body = {
        "schema_version": 1,
        "snapshot_id": "snap-test",
        "generated_at": "2026-07-28T00:00:00Z",
        "entries": [
            {
                "source": s,
                "url": f"https://example.com/{s}.json",
                "sha256": "0" * 64,
                "size_bytes": 64,
                "kind": "advisory-list",
                "revision": "r1",
            }
            for s in sources
        ],
    }
    body_for_hash = {k: v for k, v in body.items() if k != "payload_sha256"}
    body["payload_sha256"] = sha256_hex(canonical_json(body_for_hash))
    return body


class FetcherTests(unittest.TestCase):
    def test_non_https_url_rejected(self):
        with self.assertRaises(FetchError):
            fetch_https("http://example.com/x", allowed_hosts={"example.com"})

    def test_non_allowlisted_host_rejected(self):
        with self.assertRaises(FetchError):
            fetch_https("https://attacker.example.com/x",
                        allowed_hosts={"allowed.example.com"})

    def test_socket_blocked_blocks_network(self):
        """Patching socket.socket prevents any real network call."""
        class _Blocked(socket.socket):
            def __init__(self, *args, **kwargs):
                raise FetchError("offline guard: socket blocked")
            def __getattribute__(self, name):
                raise FetchError("offline guard: socket blocked")
        with patch("socket.socket", _Blocked):
            with self.assertRaises(FetchError):
                fetch_https("https://scs.owasp.org/x",
                            allowed_hosts={"scs.owasp.org"})


class ManifestTests(unittest.TestCase):
    def test_verify_good_manifest(self):
        m = verify_manifest(_good_manifest())
        self.assertEqual(m.snapshot_id, "snap-test")
        self.assertEqual(len(m.entries), 1)

    def test_pinned_hash_mismatch_rejected(self):
        manifest = _good_manifest()
        with self.assertRaises(ManifestError):
            verify_manifest(manifest, pinned_payload_hash="0" * 64)

    def test_http_url_rejected_in_manifest(self):
        manifest = _good_manifest()
        manifest["entries"][0]["url"] = "http://example.com/x"
        manifest["payload_sha256"] = sha256_hex(canonical_json({k: v for k, v in manifest.items() if k != "payload_sha256"}))
        with self.assertRaises(ManifestError):
            verify_manifest(manifest)


class ValidatorTests(unittest.TestCase):
    def test_required_fields_missing(self):
        with self.assertRaises(ValueError):
            validate_record({"source": "x", "title": "y", "content_sha256": "abc"})

    def test_unknown_fields_dropped(self):
        record = {
            "advisory_id": "ADV-1",
            "source": "test",
            "title": "T",
            "content_sha256": "abc",
            "_dangerous": "rm -rf /",
        }
        cleaned = validate_record(record)
        self.assertNotIn("_dangerous", cleaned)

    def test_record_list_accepts_bare_and_wrapped(self):
        records = [
            {"advisory_id": "A", "source": "s", "title": "t", "content_sha256": "c"}
        ]
        self.assertEqual(len(validate_record_list(records)["records"]), 1)
        wrapped = {"records": records}
        self.assertEqual(len(validate_record_list(wrapped)["records"]), 1)


class InstallTests(unittest.TestCase):
    def test_install_and_activate(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Cache(base=Path(tmp) / "intel")
            manifest = _good_manifest()
            record = {
                "advisory_id": "ADV-1",
                "source": "owasp-scs",
                "title": "Test",
                "summary": "Test advisory",
                "cwes": ["CWE-79"],
                "content_sha256": "abc",
            }
            snap = install_snapshot(
                manifest,
                per_source_payloads={"owasp-scs": {"records": [record]}},
                cache=cache,
            )
            self.assertTrue((snap.path / "meta.json").exists())
            # Latest should resolve
            latest = cache.latest()
            self.assertEqual(latest.snapshot_id, snap.snapshot_id)


if __name__ == "__main__":
    unittest.main()