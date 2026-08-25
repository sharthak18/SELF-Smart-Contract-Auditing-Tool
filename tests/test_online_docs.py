"""Local doc inventory + opt-in online fetch (never used by default scan)."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from self_tool.autonomous.online import (
    OnlineError,
    _assert_public_host,
    _osv_severity,
    _vuln_to_hit,
    enrich_with_online,
)
from self_tool.autonomous.pipeline import run_autonomous_audit
from self_tool.core.doc_reader import build_protocol_context, merge_brief_from_text
from self_tool.core.local_docs import extract_pdf_text, extract_urls, html_to_text
from self_tool.core.protocol_context import ProtocolContext


ROOT = Path(__file__).resolve().parents[1]


def _minimal_pdf(text: str) -> bytes:
    payload = f"BT /F1 12 Tf 10 100 Td ({text}) Tj ET\n"
    return (
        b"%PDF-1.1\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 200 200]/Parent 2 0 R/Contents 4 0 R>>endobj\n"
        + f"4 0 obj<</Length {len(payload)}>>stream\n".encode("ascii")
        + payload.encode("latin-1")
        + b"endstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
    )


class LocalDocInventoryTests(unittest.TestCase):
    def test_pdf_and_links_are_acknowledged_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "audits").mkdir()
            (root / "src").mkdir()
            (root / "README.md").write_text(
                "# Demo\n\nDocs: https://docs.example.com/protocol\n"
                "Prior review: https://github.com/org/repo/blob/main/audits/spearbit.pdf\n",
                encoding="utf-8",
            )
            (root / "audits" / "spearbit-2025.pdf").write_bytes(
                _minimal_pdf("Known issue: first depositor inflation is accepted.")
            )
            (root / "src" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Vault { function deposit() external {} }\n",
                encoding="utf-8",
            )
            ctx = build_protocol_context(str(root / "src"))
            self.assertTrue(any("docs.example.com" in url for url in ctx.referenced_urls), ctx.referenced_urls)
            self.assertTrue(any("spearbit" in path for path in ctx.local_audit_files), ctx.local_audit_files)
            self.assertTrue(ctx.has_audit_history)
            self.assertTrue(
                any("first depositor" in item.lower() for item in ctx.known_issues)
                or ctx.has_audit_history
            )

    def test_pdf_extractor_reads_tj_literals(self):
        text = extract_pdf_text(_minimal_pdf("Chainlink oracles can provide outdated answers"))
        self.assertIn("outdated answers", text)

    def test_html_to_text_strips_tags(self):
        text = html_to_text("<html><script>alert(1)</script><h1>Vault</h1><p>Uses a TWAP.</p>")
        self.assertIn("Vault", text)
        self.assertIn("TWAP", text)
        self.assertNotIn("alert", text)

    def test_extract_urls_skips_images(self):
        urls = extract_urls("see https://x.com/a.png and https://docs.foo.io/guide")
        self.assertEqual(urls, ["https://docs.foo.io/guide"])

    def test_merge_brief_from_fetched_known_issues(self):
        ctx = ProtocolContext()
        merge_brief_from_text(ctx, """
# Fetched

## Known Issues

- Fee-on-transfer tokens are not supported.
""")
        self.assertTrue(ctx.known_issues)
        self.assertIn("AV-FEE-ON-TRANSFER", ctx.accepted_playbooks)


class OnlineEnrichmentTests(unittest.TestCase):
    def test_enrichment_uses_injected_fetcher_and_osv(self):
        ctx = ProtocolContext()
        ctx.referenced_urls = ["https://docs.example.com/protocol"]

        def fake_fetch(url):
            self.assertEqual(url, "https://docs.example.com/protocol")
            return (
                b"# Protocol\n\n## Known Issues\n\n- Storage gap in the upgradeable base is known.\n",
                "text/markdown",
            )

        def fake_osv(name, version, ecosystem):
            self.assertEqual(name, "lodash")
            return [{
                "id": "GHSA-test-lodash",
                "summary": "Prototype pollution",
                "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                "references": [{"url": "https://github.com/advisories/GHSA-test-lodash"}],
            }]

        result = enrich_with_online(
            ctx,
            packages=[("lodash", "4.17.20", "npm", "package.json")],
            fetcher=fake_fetch,
            osv_query=fake_osv,
        )
        self.assertTrue(result.refs[0].ok)
        self.assertIn("AV-STORAGE-COLLISION", ctx.accepted_playbooks)
        self.assertEqual(1, len(result.osv_hits))
        self.assertEqual("HIGH", result.osv_hits[0].severity)
        self.assertTrue(result.osv_hits[0].id.startswith("AUTO-DEP-OSV-"))

    def test_private_hosts_are_refused(self):
        with self.assertRaises(OnlineError):
            _assert_public_host("localhost")
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, 0, 0, "", ("127.0.0.1", 443))]):
            with self.assertRaises(OnlineError):
                _assert_public_host("evil.internal.example")

    def test_osv_severity_from_cvss(self):
        self.assertEqual("CRITICAL", _osv_severity({"severity": [{"score": "9.8"}]}))
        self.assertEqual("HIGH", _osv_severity({"database_specific": {"severity": "HIGH"}}))

    def test_vuln_without_id_is_ignored(self):
        self.assertIsNone(_vuln_to_hit({}, "x", "1", "npm", "package.json"))

    def test_pipeline_online_does_not_call_network_when_injected_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Vault.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Vault { function deposit() external {} }\n",
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "# Vault\n\nhttps://docs.example.com/vault\n", encoding="utf-8",
            )
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"lodash": "4.17.20"}}), encoding="utf-8",
            )

            def fake_fetch(url):
                return b"# Docs\n\nA lending vault.\n", "text/markdown"

            def fake_osv(name, version, ecosystem):
                return []

            with patch("self_tool.autonomous.online.fetch_https_text", fake_fetch), \
                 patch("self_tool.autonomous.online.query_osv", fake_osv):
                audit = run_autonomous_audit(
                    str(root), output=str(root / "out.md"),
                    no_docs=False, online=True, skip_static=True, index_root=root,
                )
        self.assertTrue(audit.understanding.referenced_urls)
        self.assertTrue(any(item.startswith("online:") for item in audit.diagnostics), audit.diagnostics)


class OfflineGuardOnlineTests(unittest.TestCase):
    def test_default_autonomous_does_not_import_online(self):
        script = """
import json, sys, tempfile
from pathlib import Path
from self_tool.autonomous.pipeline import run_autonomous_audit
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    (root / 'A.sol').write_text('pragma solidity ^0.8.20;\\ncontract A { function x() external {} }\\n')
    run_autonomous_audit(str(root), output=str(root / 'out.md'), no_docs=True, index_root=root, skip_static=True)
print(json.dumps(sorted(name for name in sys.modules if name.startswith('self_tool.autonomous.online') or name.startswith('self_tool.intelligence'))))
"""
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=str(ROOT),
            text=True, capture_output=True, check=True,
        )
        self.assertEqual(result.stdout.strip(), "[]", result.stderr)


class LanguageReasonerTests(unittest.TestCase):
    def _audit(self, tmp: str, source: str, name: str):
        path = Path(tmp) / name
        path.write_text(source, encoding="utf-8")
        return run_autonomous_audit(
            str(path), output=str(Path(tmp) / "out.md"),
            no_docs=True, skip_static=True, index_root=Path(tmp),
        )

    def test_vyper_vulnerable_compiler_is_flagged(self):
        src = "# @version 0.2.16\n\n@external\ndef drain():\n    raw_call(msg.sender, b\"\", value=self.balance)\n"
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "Pool.vy")
        self.assertIn("vyper", audit.understanding.languages)
        self.assertTrue(audit.understanding.facts.get("vyper_vulnerable_compiler"), audit.understanding.facts)
        self.assertIn("AUTO-VYPER-COMPILER", {item.id for item in audit.findings})

    def test_huff_stack_playbook_fires(self):
        src = "#define macro MAIN() = takes(0) returns(0) {\n    CALLVALUE\n    JUMP\n}\n"
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "Main.huff")
        self.assertIn("huff", audit.understanding.languages)
        self.assertTrue(audit.understanding.facts.get("is_huff"))
        self.assertIn("AUTO-HUFF-STACK", {item.id for item in audit.findings})

    def test_move_unauth_write_is_flagged(self):
        src = """
module demo::vault {
    public entry fun drain(addr: address) {
        let v = borrow_global_mut<Vault>(addr);
        v.bal = 0;
    }
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "vault.move")
        self.assertIn("move", audit.understanding.languages)
        self.assertTrue(audit.understanding.facts.get("move_unauth_write"), audit.understanding.facts)
        self.assertIn("AUTO-MOVE-CAPABILITY", {item.id for item in audit.findings})

    def test_rust_missing_signer_fact(self):
        src = """
use solana_program::account_info::AccountInfo;
pub fn withdraw(authority: AccountInfo, vault: AccountInfo) {
    invoke(&ix, &[authority, vault]);
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "lib.rs")
        self.assertIn("rust", audit.understanding.languages)
        self.assertTrue(
            audit.understanding.facts.get("solana_missing_signer_or_cpi")
            or audit.understanding.facts.get("solana_alias_or_sysvar_risk"),
            audit.understanding.facts,
        )


if __name__ == "__main__":
    unittest.main()
