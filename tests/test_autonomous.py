"""Tests for the autonomous AI auditor."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from click.testing import CliRunner

from self_tool.autonomous.brain import (
    brain_stats,
    load_attack_vectors,
    load_expert_tactics,
    load_incidents,
    retrieve,
)
from self_tool.autonomous.dependencies import scan_dependencies, version_in_range
from self_tool.autonomous.ingest import ingest_project
from self_tool.autonomous.models import ManifestFile
from self_tool.autonomous.pipeline import exit_code_for, run_autonomous_audit
from self_tool.autonomous.trainer import INDEX_SCHEMA, ensure_trained, index_path, train
from self_tool.core.scanner import discover_files
from self_tool.cli.autonomous import autonomous as autonomous_cmd
from self_tool.cli.autonomous import train as train_cmd


ROOT = Path(__file__).resolve().parents[1]
VAULT = ROOT / "tests" / "contracts" / "VulnerableVault.sol"
CURVE = ROOT / "tests" / "contracts" / "VulnerableCurve.vy"
RECENT = ROOT / "tests" / "contracts" / "RecentLogicBugs.sol"


class BrainTests(unittest.TestCase):
    def test_playbooks_load_and_are_unique(self):
        playbooks = load_attack_vectors()
        self.assertGreaterEqual(len(playbooks), 35)
        ids = [item.id for item in playbooks]
        self.assertEqual(len(ids), len(set(ids)))
        for item in playbooks:
            self.assertTrue(item.description)
            self.assertTrue(item.exploit)
            self.assertTrue(item.remediation)
            self.assertTrue(item.proof_obligation)

    def test_incidents_and_tactics_load(self):
        incidents = load_incidents()
        tactics = load_expert_tactics()
        self.assertGreaterEqual(len(incidents), 15)
        self.assertGreaterEqual(len(tactics), 10)
        self.assertEqual(len(incidents), len({item["id"] for item in incidents}))
        self.assertEqual(len(tactics), len({item["id"] for item in tactics}))
        self.assertTrue(any(item["id"] == "INC-EULER-2023" for item in incidents))
        self.assertTrue(any(item["id"] == "TAC-IMMUNEFI-LOGIC" for item in tactics))
        for item in incidents:
            self.assertTrue(item["lesson"])
            self.assertNotIn("payload", json.dumps(item).lower())
        for item in tactics:
            self.assertTrue(item["questions"])

    def test_brain_stats_cover_every_corpus(self):
        stats = brain_stats()
        self.assertGreaterEqual(stats["exploits"], 1)
        self.assertGreaterEqual(stats["languages"], 5)
        self.assertGreaterEqual(stats["dependency_advisories"], 5)
        self.assertGreaterEqual(stats["incidents"], 15)
        self.assertGreaterEqual(stats["expert_tactics"], 10)
        self.assertGreaterEqual(stats["attack_vectors"], 35)

    def test_retrieval_ranks_reentrancy_for_a_vault_query(self):
        hits = retrieve(
            "permissionless withdraw call value before balance update reentrancy vault",
            index=None,
            limit=5,
        )
        self.assertTrue(hits)
        blob = " ".join(item.doc_id + item.title for item in hits).lower()
        self.assertTrue("reentran" in blob or "oracle" in blob or "depositor" in blob)

    def test_retrieval_links_euler_donation_incident(self):
        hits = retrieve(
            "donateToReserves skipped health check flash loan self-liquidate euler lending",
            index=None,
            limit=8,
        )
        self.assertTrue(hits)
        blob = " ".join(item.doc_id + item.title + item.kind for item in hits).lower()
        self.assertTrue(
            "euler" in blob or "donation" in blob or "liquidate" in blob,
            blob,
        )


class DependencyTests(unittest.TestCase):
    def test_version_range_parser(self):
        self.assertTrue(version_in_range("0.2.16", ">=0.2.15,<0.3.1"))
        self.assertFalse(version_in_range("0.3.1", ">=0.2.15,<0.3.1"))
        self.assertTrue(version_in_range("0.3.7", "==0.3.7"))
        self.assertTrue(version_in_range("4.8.0", ">=4.3.0,<4.8.3"))
        self.assertFalse(version_in_range("4.9.0", ">=4.3.0,<4.8.3"))
        self.assertTrue(version_in_range("1.2.3", "*"))

    def test_npm_lock_matches_openzeppelin_advisory(self):
        manifest = ManifestFile(
            relative_path="package.json",
            kind="npm",
            content=json.dumps({
                "dependencies": {
                    "@openzeppelin/contracts": "4.8.0",
                }
            }),
        )
        hits = scan_dependencies([manifest])
        packages = {hit.package for hit in hits}
        self.assertIn("@openzeppelin/contracts", packages)
        self.assertTrue(any(hit.severity in {"HIGH", "CRITICAL", "MEDIUM"} for hit in hits))

    def test_vyper_pin_matches_compiler_advisory(self):
        manifest = ManifestFile(
            relative_path="requirements.txt",
            kind="pip",
            content="vyper==0.2.16\n",
        )
        hits = scan_dependencies([manifest])
        self.assertTrue(any(hit.package == "vyper" for hit in hits))


class IngestAndUnderstandTests(unittest.TestCase):
    def test_ingest_reads_manifests_and_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text(
                VAULT.read_text(encoding="utf-8"), encoding="utf-8",
            )
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"@openzeppelin/contracts": "4.8.0"}}),
                encoding="utf-8",
            )
            (root / "README.md").write_text("# Demo Vault\n\nA lending vault.\n", encoding="utf-8")
            ingestion = ingest_project(str(root))
            self.assertTrue(ingestion.files)
            kinds = {item.kind for item in ingestion.manifests}
            self.assertIn("foundry", kinds)
            self.assertIn("npm", kinds)
            self.assertIn("solidity", ingestion.languages)

    def test_cairo_files_are_ingested_without_changing_default_scanner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Main.sol").write_text("contract Main {}", encoding="utf-8")
            (root / "src" / "Bank.cairo").write_text(
                "#[external(v0)]\nfn set_owner() {}\n", encoding="utf-8",
            )
            files, _ = discover_files(str(root))
            self.assertEqual(["src/Main.sol"], [item.relative_path for item in files])
            ingestion = ingest_project(str(root))
            extras = [item.relative_path for item in ingestion.extra_source]
            self.assertIn("src/Bank.cairo", extras)


class PipelineTests(unittest.TestCase):
    def test_autonomous_audit_on_vulnerable_vault_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["SELF_DATA_DIR"] = tmp
            try:
                out1 = str(Path(tmp) / "one.md")
                out2 = str(Path(tmp) / "two.md")
                first = run_autonomous_audit(
                    str(VAULT), output=out1, also_json=True, no_docs=True, index_root=Path(tmp),
                )
                second = run_autonomous_audit(
                    str(VAULT), output=out2, also_json=True, no_docs=True, index_root=Path(tmp),
                )
                self.assertEqual(
                    [item.id for item in first.findings],
                    [item.id for item in second.findings],
                )
                self.assertEqual(first.project_fingerprint, second.project_fingerprint)
                self.assertTrue(first.static_issues)
                self.assertTrue(first.findings)
                ids = {item.id for item in first.findings}
                self.assertTrue(
                    any(name.startswith("AUTO-REENTRANCY") or name.startswith("AUTO-ACCESS")
                        or name.startswith("AUTO-TX-ORIGIN") or name.startswith("AUTO-SELFDESTRUCT")
                        for name in ids),
                    ids,
                )
                self.assertGreaterEqual(len(first.understanding.contracts), 1)
                self.assertIn("solidity", first.understanding.languages)
                report = Path(first.trained_on["report_path"])
                self.assertTrue(report.exists())
                self.assertTrue(report.with_suffix(".json").exists())
            finally:
                os.environ.pop("SELF_DATA_DIR", None)

    def test_autonomous_reads_vyper_and_flags_compiler_or_reentrancy(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = run_autonomous_audit(
                str(CURVE), output=str(Path(tmp) / "vy.md"), no_docs=True, index_root=Path(tmp),
            )
        self.assertIn("vyper", audit.understanding.languages)
        blob = " ".join(item.id for item in audit.findings).lower()
        self.assertTrue(
            "reentran" in blob or "vyper" in blob or "access" in blob,
            blob,
        )

    def test_llm_module_is_not_imported_unless_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Drop any previous import so the assertion is meaningful.
            sys.modules.pop("self_tool.autonomous.llm", None)
            run_autonomous_audit(
                str(VAULT), output=str(Path(tmp) / "nollm.md"),
                no_docs=True, index_root=Path(tmp), use_llm=False,
            )
            self.assertNotIn("self_tool.autonomous.llm", sys.modules)

    def test_exit_code_critical(self):
        from self_tool.autonomous.models import AutonomousAudit, ProtocolUnderstanding

        understanding = ProtocolUnderstanding(
            name="x", types=["vault"], summary="", languages=["solidity"],
            contracts=[], facts={}, token_flows=[], invariants=[], math_formulas=[],
            privileged_ops=[], permissionless_ops=[], external_deps=[],
            architecture_notes=[], source_chars=0, file_count=0,
        )
        from self_tool.autonomous.models import AutonomousFinding
        finding = AutonomousFinding(
            id="AUTO-X", title="t", severity="CRITICAL", confidence="High",
            file="A.sol", line=1, language="solidity", snippet="", description="",
            exploit_scenario="", remediation="", proof_obligation="",
            regression_recipe="", source="symbolic",
        )
        audit = AutonomousAudit(
            version="2.4.0", target=".", project_fingerprint="pf_x",
            understanding=understanding, static_issues=[], findings=[finding],
            exploit_paths=[], dependencies=[], retrieved=[], trained_on={},
            llm_used=False, llm_error="", elapsed=0.0,
        )
        self.assertEqual(2, exit_code_for(audit))


class TrainerTests(unittest.TestCase):
    def test_train_builds_persistent_index_and_ingests_extra_docs(self):
        with tempfile.TemporaryDirectory() as tmp:
            extra = Path(tmp) / "extra.json"
            extra.write_text(json.dumps({
                "documents": [
                    {"id": "DOC-1", "kind": "note", "title": "rounding",
                     "text": "division before multiplication steals dust"}
                ]
            }), encoding="utf-8")
            index = train([extra], root=Path(tmp), include_feedback=False)
            self.assertGreater(index.document_count, 10)
            self.assertEqual(INDEX_SCHEMA, index.schema_version)
            self.assertTrue(any(doc["id"] == "DOC-1" for doc in index.documents))
            self.assertTrue(any(doc["id"] == "INC-EULER-2023" for doc in index.documents))
            self.assertTrue(any(doc["id"] == "TAC-TOB-THREAT-MODEL" for doc in index.documents))
            self.assertGreater(index.playbook_weights.get("AV-DONATION-HEALTH", 1.0), 1.0)
            self.assertLessEqual(index.playbook_weights.get("AV-DONATION-HEALTH", 1.0), 1.15)
            self.assertIn("bundled-incidents", index.sources)
            self.assertIn("bundled-expert-tactics", index.sources)
            self.assertTrue(index_path(Path(tmp)).is_file())
            again = ensure_trained(root=Path(tmp))
            self.assertEqual(index.document_count, again.document_count)


class OfflineGuardExtensionTests(unittest.TestCase):
    def test_default_scan_does_not_import_autonomous(self):
        script = """
import json, sys, tempfile
from pathlib import Path
from self_tool.core.scanner import discover_files
from self_tool.core.detector_engine import DetectorEngine
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    (root / 'A.sol').write_text('pragma solidity ^0.8.0;\\ncontract A {}\\n')
    files, _ = discover_files(str(root))
    DetectorEngine().run(files)
print(json.dumps(sorted(name for name in sys.modules if name.startswith('self_tool.autonomous'))))
"""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=str(ROOT),
            text=True, capture_output=True, check=True,
        )
        self.assertEqual(result.stdout.strip(), "[]")


class CliTests(unittest.TestCase):
    def test_autonomous_cli_on_single_file(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            Path("Risk.sol").write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Risk {\n"
                "    function destroy() external { selfdestruct(payable(msg.sender)); }\n"
                "    function withdraw() external {\n"
                "        (bool ok,) = msg.sender.call{value: 1}(\"\");\n"
                "        require(ok);\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            with tempfile.TemporaryDirectory() as tmp:
                env = {"SELF_DATA_DIR": tmp}
                result = runner.invoke(autonomous_cmd, [
                    "Risk.sol", "--no-docs", "--quiet",
                ], env=env)
            self.assertIn(result.exit_code, {1, 2}, result.output)
            self.assertTrue(Path("self-autonomous.md").exists())

    def test_train_status_without_index(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            result = runner.invoke(train_cmd, ["--status"], env={"SELF_DATA_DIR": tmp})
        self.assertEqual(0, result.exit_code)
        self.assertIn("no trained index", result.output)


if __name__ == "__main__":
    unittest.main()
