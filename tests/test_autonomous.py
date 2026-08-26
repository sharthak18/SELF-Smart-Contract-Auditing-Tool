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

    def test_foundry_solc_via_ir_matches_tstore_poison_advisory(self):
        manifest = ManifestFile(
            relative_path="foundry.toml",
            kind="foundry",
            content='[profile.default]\nsolc = "0.8.30"\nvia_ir = true\n',
        )
        hits = scan_dependencies([manifest])
        self.assertTrue(any(hit.package == "solc" and hit.severity == "CRITICAL" for hit in hits))

    def test_foundry_solc_without_via_ir_does_not_match(self):
        manifest = ManifestFile(
            relative_path="foundry.toml",
            kind="foundry",
            content='[profile.default]\nsolc = "0.8.30"\n',
        )
        hits = scan_dependencies([manifest])
        self.assertFalse(any(hit.package == "solc" for hit in hits))

    def test_foundry_solc_fixed_version_does_not_match(self):
        manifest = ManifestFile(
            relative_path="foundry.toml",
            kind="foundry",
            content='[profile.default]\nsolc = "0.8.34"\nvia_ir = true\n',
        )
        hits = scan_dependencies([manifest])
        self.assertFalse(any(hit.package == "solc" for hit in hits))


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
            version="2.5.0", target=".", project_fingerprint="pf_x",
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

class ReplayFixTests(unittest.TestCase):
    """Facts and playbooks learned from the 10-contest C4 replay."""

    def _audit(self, tmp: str, source: str, name: str = "Case.sol"):
        root = Path(tmp)
        path = root / name
        path.write_text(source, encoding="utf-8")
        return run_autonomous_audit(
            str(path), output=str(root / "out.md"), no_docs=True, index_root=root,
        )

    def test_user_supplied_domain_separator_is_critical(self):
        src = """
        pragma solidity ^0.8.20;
        contract Forwarder {
            function execute(
                address from,
                bytes32 domainSeparator,
                bytes32 requestTypeHash,
                bytes calldata suffixData,
                bytes calldata sig
            ) external {
                bytes32 digest = keccak256(abi.encodePacked("\\x19\\x01", domainSeparator, requestTypeHash));
                address signer = ecrecover(digest, 27, bytes32(0), bytes32(0));
                require(signer == from);
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "Forwarder.sol")
        self.assertTrue(audit.understanding.facts.get("user_supplied_domain_separator"), audit.understanding.facts)
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-DOMAIN-SEPARATOR-ARG", ids, ids)

    def test_public_erc20_mint_is_not_missing_access(self):
        src = """
        pragma solidity ^0.8.20;
        contract Token {
            mapping(address => uint256) public balanceOf;
            function mint(address to, uint256 amount) external {
                balanceOf[to] += amount;
            }
            function burn(address from, uint256 amount) external {
                balanceOf[from] -= amount;
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "Token.sol")
        self.assertFalse(audit.understanding.facts.get("unguarded_privileged_write"))
        ids = {item.id for item in audit.findings}
        self.assertNotIn("AUTO-ACCESS-MISSING", ids, ids)

    def test_admin_setter_without_auth_still_flags(self):
        src = """
        pragma solidity ^0.8.20;
        contract Admin {
            address public owner;
            function setOwner(address next) external {
                owner = next;
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "Admin.sol")
        self.assertTrue(audit.understanding.facts.get("unguarded_privileged_write"))
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-ACCESS-MISSING", ids, ids)

    def test_amount_out_minimum_zero_is_slippage(self):
        src = """
        pragma solidity ^0.8.20;
        interface ISwap {
            struct ExactInputParams { uint256 amountOutMinimum; }
            function exactInputSingle(ExactInputParams calldata) external returns (uint256);
        }
        contract Vault {
            ISwap public router;
            function harvest() external {
                router.exactInputSingle(ISwap.ExactInputParams({amountOutMinimum: 0}));
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "Vault.sol")
        self.assertTrue(audit.understanding.facts.get("amount_out_min_zero"))
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-SLIPPAGE", ids, ids)

    def test_chainlink_hardcoded_1e18_is_decimal_mismatch(self):
        src = """
        pragma solidity ^0.8.20;
        interface AggregatorV3 { function latestRoundData() external view returns (uint80,int256,uint256,uint256,uint80); }
        contract EthOracle {
            AggregatorV3 public feed;
            function getPrecision() public pure returns (uint256) { return 10 ** 18; }
            function getPrice() external view returns (uint256) {
                (, int256 answer,,,) = feed.latestRoundData();
                return uint256(answer);
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "EthOracle.sol")
        self.assertTrue(audit.understanding.facts.get("oracle_decimal_mismatch"))
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-ORACLE-DECIMALS", ids, ids)

    def test_permit2_without_token_check(self):
        src = """
        pragma solidity ^0.8.20;
        interface IPermit2 {
            struct PermitTransferFrom { address token; uint256 amount; }
            struct SignatureTransferDetails { address to; uint256 requestedAmount; }
            function permitTransferFrom(PermitTransferFrom calldata, SignatureTransferDetails calldata, address, bytes calldata) external;
        }
        contract V3Vault {
            IPermit2 public permit2;
            function deposit(bytes calldata permitData) external {
                (IPermit2.PermitTransferFrom memory permit, bytes memory signature) =
                    abi.decode(permitData, (IPermit2.PermitTransferFrom, bytes));
                permit2.permitTransferFrom(permit, IPermit2.SignatureTransferDetails(address(this), 1), msg.sender, signature);
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "V3Vault.sol")
        self.assertTrue(audit.understanding.facts.get("permit2_token_unbound"))
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-PERMIT2", ids, ids)

    def test_interface_liquidate_is_not_a_finding(self):
        src = """
        pragma solidity ^0.8.20;
        interface IPool {
            function liquidate(address user) external;
            function borrow(uint256 amount) external;
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "IPool.sol")
        self.assertFalse(audit.understanding.facts.get("liquidation_unrestricted"))
        ids = {item.id for item in audit.findings}
        self.assertNotIn("AUTO-LIQUIDATION-SELF", ids, ids)
        self.assertNotIn("AUTO-ACCESS-MISSING", ids, ids)

    def test_upgradeable_with_gap_skips_storage_collision(self):
        src = """
        pragma solidity ^0.8.20;
        contract Token {
            uint256[50] private __gap;
            function initialize() public initializer {}
            function upgradeTo(address impl) external { }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "Token.sol")
        self.assertFalse(audit.understanding.facts.get("missing_storage_gap"))
        ids = {item.id for item in audit.findings}
        self.assertNotIn("AUTO-STORAGE-COLLISION", ids, ids)

    def test_hardhat_wildcard_advisory_is_not_a_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Token.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Token { uint256 public x; }\n",
                encoding="utf-8",
            )
            (root / "package.json").write_text(
                json.dumps({"devDependencies": {"hardhat": "2.19.0"}}),
                encoding="utf-8",
            )
            audit = run_autonomous_audit(
                str(root), output=str(root / "out.md"), no_docs=True, index_root=root,
            )
        ids = [item.id for item in audit.findings]
        self.assertFalse(any("HARDHAT" in item for item in ids), ids)

    def test_whitelist_burn_gap(self):
        src = """
        pragma solidity ^0.8.20;
        contract UStb {
            enum TransferState { FULLY_DISABLED, WHITELIST_ENABLED, FULLY_ENABLED }
            TransferState public transferState;
            function _beforeTokenTransfer(address from, address to, uint256) internal {
                if (transferState == TransferState.WHITELIST_ENABLED) {
                    if (to == address(0)) { return; }
                }
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            audit = self._audit(tmp, src, "UStb.sol")
        self.assertTrue(audit.understanding.facts.get("whitelist_burn_gap"))
        ids = {item.id for item in audit.findings}
        self.assertIn("AUTO-WHITELIST-GAP", ids, ids)

    def test_contest_brief_is_parsed_and_honored(self):
        from self_tool.core.doc_reader import build_protocol_context

        src = """
        pragma solidity ^0.8.20;
        contract Vault {
            function deposit() external {}
            function convertToShares(uint256 a) external view returns (uint256) { return a; }
            function totalAssets() external view returns (uint256) { return 1; }
            function totalSupply() external view returns (uint256) { return 1; }
        }
        """
        oos = """
        pragma solidity ^0.8.20;
        interface IPool { function liquidate(address user) external; }
        """
        readme = """
# Demo Vault

## Automated Findings / Publicly Known Issues

- First depositor inflation is accepted until the deployer donates a yieldBuffer.
- Lack of storage gap in the upgradeable base is known.

## All trusted roles in the protocol

| Role | Description |
| --- | --- |
| OWNER | Multisig admin |
| KEEPER | Trusted keeper |

## Files out of scope

| File |
| --- |
| ./contracts/interfaces/IPool.sol |
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "contracts").mkdir()
            (root / "contracts" / "interfaces").mkdir(parents=True)
            (root / "README.md").write_text(readme, encoding="utf-8")
            (root / "out_of_scope.txt").write_text(
                "./contracts/interfaces/IPool.sol\n", encoding="utf-8",
            )
            (root / "contracts" / "Vault.sol").write_text(src, encoding="utf-8")
            (root / "contracts" / "interfaces" / "IPool.sol").write_text(oos, encoding="utf-8")
            ctx = build_protocol_context(str(root / "contracts"))
            self.assertEqual(ctx.docs_root, str(root))
            self.assertTrue(any("yieldBuffer" in item or "first depositor" in item.lower() for item in ctx.known_issues))
            self.assertIn("OWNER", ctx.trusted_roles)
            self.assertIn("AV-FIRST-DEPOSITOR", ctx.accepted_playbooks)
            self.assertTrue(any("IPool.sol" in path for path in ctx.out_of_scope_files))
            audit = run_autonomous_audit(
                str(root / "contracts"), output=str(root / "out.md"),
                no_docs=False, index_root=root,
            )
        self.assertTrue(audit.understanding.known_issues)
        self.assertIn("OWNER", audit.understanding.trusted_roles)
        ids = {item.id for item in audit.findings}
        self.assertNotIn("AUTO-FIRST-DEPOSITOR", ids, ids)
        self.assertFalse(any("IPool.sol" in item.file for item in audit.findings))

    def test_docs_root_prefers_contest_readme_over_nested_package(self):
        from self_tool.core.doc_reader import build_protocol_context, resolve_docs_root

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "pt-v5-vault" / "src"
            pkg.mkdir(parents=True)
            (root / "scope.txt").write_text("pt-v5-vault/src/PrizeVault.sol\n", encoding="utf-8")
            (root / "README.md").write_text(
                "# Contest\n\n## Known Issues\n\n- yieldBuffer donation covers first-depositor inflation.\n\n"
                "## All trusted roles in the protocol\n\n| Role | Description |\n| --- | --- |\n| VAULT_OWNER | Can change claimer |\n",
                encoding="utf-8",
            )
            (root / "pt-v5-vault" / "README.md").write_text(
                "# Prize Vault package\n\nInstall with forge.\n",
                encoding="utf-8",
            )
            (pkg / "PrizeVault.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract PrizeVault { function deposit() external {} }\n",
                encoding="utf-8",
            )
            self.assertEqual(resolve_docs_root(str(pkg)), root)
            ctx = build_protocol_context(str(pkg))
            self.assertEqual(ctx.docs_root, str(root))
            self.assertIn("VAULT_OWNER", ctx.trusted_roles)
            self.assertIn("AV-FIRST-DEPOSITOR", ctx.accepted_playbooks)

    def test_paragraph_known_issues_and_role_prose_are_parsed(self):
        from self_tool.core.doc_reader import build_protocol_context

        readme = """
# Lending Pair

## Automated Findings / Publicly Known Issues

The 4naly3er report can be found [here](https://example.com/4naly3er-report.md).

## Known Issues

### Misconfigured Oracles

It is possible to misconfigure pairs and choose oracles and oracle normalization
that do not match the assets.

### Chainlink Oracle

Chainlink oracles can provide outdated answers.

## Additional Context

- Roles in the protocol: Owner (which will be set to a Multisig and Timelock), EmergencyAdmin, Operators
- Special ERC20 tokens like fee-on-transfer or rebasing tokens are not supported.
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "README.md").write_text(readme, encoding="utf-8")
            (root / "src" / "Pair.sol").write_text(
                "pragma solidity ^0.8.20;\ncontract Pair {}\n", encoding="utf-8",
            )
            ctx = build_protocol_context(str(root / "src"))
        blob = " ".join(ctx.known_issues).lower()
        self.assertTrue("misconfigure" in blob or "outdated" in blob, ctx.known_issues)
        self.assertIn("Owner", ctx.trusted_roles)
        self.assertIn("EmergencyAdmin", ctx.trusted_roles)
        self.assertNotIn("Timelock)", ctx.trusted_roles)
        self.assertIn("AV-ORACLE-SPOT", ctx.accepted_playbooks)
        self.assertIn("AV-L2-SEQUENCER", ctx.accepted_playbooks)
        self.assertIn("AV-FEE-ON-TRANSFER", ctx.accepted_playbooks)

    def test_accepted_governance_playbook_skips_flash_vote_path(self):
        from self_tool.autonomous.exploit_paths import synthesize_paths
        from self_tool.autonomous.models import ProtocolUnderstanding

        understanding = ProtocolUnderstanding(
            name="x", types=["governance"], summary="", languages=["solidity"],
            contracts=[], facts={"is_governance": True, "votes_not_checkpointed": True},
            token_flows=[], invariants=[], math_formulas=[],
            privileged_ops=[], permissionless_ops=["vote"], external_deps=[],
            architecture_notes=[], source_chars=0, file_count=0,
            accepted_playbooks=["AV-GOVERNANCE-FLASH"],
        )
        paths = synthesize_paths(understanding, [], [])
        self.assertFalse(any(item.id == "PATH-FLASH-VOTE" for item in paths), [p.id for p in paths])

    def test_train_status_without_index(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            result = runner.invoke(train_cmd, ["--status"], env={"SELF_DATA_DIR": tmp})
        self.assertEqual(0, result.exit_code)
        self.assertIn("no trained index", result.output)


if __name__ == "__main__":
    unittest.main()
