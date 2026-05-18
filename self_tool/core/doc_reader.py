"""
SELF — Doc Reader
Reads all project documentation and NatSpec to build a ProtocolContext.

Reads:
  - README.md, README.rst, README.txt
  - docs/*.md, WHITEPAPER.md, SECURITY.md, ARCHITECTURE.md
  - audits/*.md, audits/*.pdf (text extraction)
  - NatSpec comments in all source files (/// @dev, @notice, @custom:security)
  - Import statements (SafeERC20, ReentrancyGuard, etc.)
  - foundry.toml, hardhat.config.js

This runs before any detector — it builds the "brain" that makes SELF smart.
"""

import os
import re
from pathlib import Path
from typing import List, Optional

from self_tool.core.protocol_context import ProtocolContext


# ── Signal keyword maps ────────────────────────────────────────────────────

MULTISIG_SIGNALS = [
    'gnosis safe', 'gnosis-safe', 'multisig', 'multi-sig', 'multi sig',
    'safe wallet', '3-of-5', '4-of-7', '5-of-9', 'n-of-m',
]

TIMELOCK_SIGNALS = [
    'timelock', 'time lock', 'timelockcontroller', '48 hour', '48h',
    '24 hour', '24h', 'time delay', 'delay period',
]

TWAP_SIGNALS = [
    'twap', 'time-weighted', 'time weighted average', 'uniswap twap',
    'observe(', 'consult(', 'price oracle twap',
]

CHAINLINK_SIGNALS = [
    'chainlink', 'aggregatorv3', 'latestrounddata', 'price feed',
    'chainlink oracle',
]

AUDIT_SIGNALS = [
    'audited by', 'security audit', 'audit report', 'has been audited',
    'reviewed by', 'code4rena', 'sherlock', 'spearbit', 'trail of bits',
    'openzeppelin audit', 'certora',
]

PAUSE_SIGNALS = [
    'emergency pause', 'pause()', 'pausable', 'circuit breaker',
    'emergency stop', 'emergency mode',
]

REBASING_SIGNALS = [
    'rebasing', 'rebase', 'elastic supply', 'ampleforth', 'rebase token',
]

FOT_SIGNALS = [
    'fee on transfer', 'fee-on-transfer', 'deflationary token',
    'transfer fee', 'supports fot',
]

STANDARD_ERC20_SIGNALS = [
    'only standard erc20', 'standard erc20 only', 'no fee-on-transfer',
    'no deflationary', 'compliant erc20',
]

PROTOCOL_TYPE_SIGNALS = {
    'amm':       ['amm', 'dex', 'swap', 'liquidity pool', 'automated market maker',
                  'uniswap', 'curve', 'balancer', 'constant product'],
    'lending':   ['lending', 'borrowing', 'collateral', 'liquidat', 'money market',
                  'aave', 'compound', 'ctoken', 'atoken', 'loan protocol'],
    'bridge':    ['bridge', 'cross-chain', 'cross chain', 'layerzero', 'wormhole',
                  'axelar', 'stargate', 'message passing', 'omnichain'],
    'staking':   ['staking', 'stake', 'yield', 'reward', 'farm', 'vault',
                  'liquid staking', 'validator', 'delegat'],
    'nft':       ['nft', 'erc-721', 'erc721', 'nonfungible', 'marketplace',
                  'collection', 'mint nft', 'token id'],
    'governance':['governance', 'governor', 'dao', 'voting', 'proposal',
                  'timelock', 'delegate vote'],
    'derivative':['perpetual', 'futures', 'options', 'derivative', 'leverage',
                  'margin', 'funding rate', 'gmx', 'synthetics'],
}

# NatSpec suppression tags (from @dev or @custom:security)
NATSPEC_SUPPRESS_TAGS = {
    'permissionless': 'permissionless',
    'intentionally permissionless': 'permissionless',
    'by design': 'by_design',
    'no auth by design': 'permissionless',
    'no deadline': 'no_deadline',
    'deadline checked elsewhere': 'no_deadline',
    'deadline in router': 'no_deadline',
    'centralized by design': 'centralized_by_design',
    'owner is multisig': 'multisig_owner',
    'reentrancy not possible': 'reentrancy_safe',
    'no reentrancy risk': 'reentrancy_safe',
    'trusted token only': 'trusted_token',
    'whitelist only': 'whitelist_only',
}


class DocReader:
    """Reads project documentation and source NatSpec to build a ProtocolContext."""

    def __init__(self, project_root: str):
        self.root = Path(project_root).resolve()
        self.ctx = ProtocolContext()

    def build(self) -> ProtocolContext:
        """Full pipeline: read all docs → extract signals → return context."""
        self._read_doc_files()
        self._read_source_natspec()
        self._read_source_imports()
        self._detect_protocol_type()
        self.ctx.build_suppressions()
        return self.ctx

    # ── Documentation reading ──────────────────────────────────────────────

    def _read_doc_files(self):
        """Read README, docs/, WHITEPAPER, SECURITY, audit reports."""
        doc_candidates = [
            'README.md', 'README.rst', 'README.txt', 'README',
            'WHITEPAPER.md', 'whitepaper.md', 'Whitepaper.md',
            'SECURITY.md', 'security.md',
            'ARCHITECTURE.md', 'architecture.md',
            'DESIGN.md', 'design.md',
        ]

        all_text = []
        security_text = []

        for fname in doc_candidates:
            fpath = self.root / fname
            if fpath.exists():
                text = self._safe_read(fpath)
                all_text.append(text)
                if 'SECURITY' in fname.upper() or 'security' in fname.lower():
                    security_text.append(text)

        # docs/ directory
        for docs_dir in ['docs', 'documentation', 'doc']:
            docs_path = self.root / docs_dir
            if docs_path.is_dir():
                for md_file in docs_path.rglob('*.md'):
                    text = self._safe_read(md_file)
                    all_text.append(text)

        # audits/ directory
        for audit_dir in ['audits', 'audit', 'reports', 'security']:
            audit_path = self.root / audit_dir
            if audit_path.is_dir():
                for audit_file in audit_path.rglob('*.md'):
                    text = self._safe_read(audit_file)
                    all_text.append(text)
                    self.ctx.has_audit_history = True

        combined = ' '.join(all_text).lower()
        self.ctx.readme_content = combined[:5000]  # Cap for LLM context
        self.ctx.security_notes = ' '.join(security_text)[:2000]

        # Extract protocol name from README h1
        for text in all_text:
            m = re.search(r'^#\s+(.+)', text, re.MULTILINE)
            if m:
                name = m.group(1).strip().strip('*_')
                if len(name) < 80:
                    self.ctx.protocol_name = name
                    break

        # Extract description (first paragraph)
        for text in all_text:
            paras = [p.strip() for p in text.split('\n\n') if p.strip() and not p.startswith('#')]
            if paras:
                self.ctx.description = paras[0][:500]
                break

        # Extract signals from combined text
        self._extract_signals_from_text(combined)

    def _extract_signals_from_text(self, text: str):
        """Extract boolean security signals from lowercased combined text."""
        def any_in(signals):
            return any(s in text for s in signals)

        self.ctx.uses_multisig = any_in(MULTISIG_SIGNALS)
        self.ctx.uses_timelock = any_in(TIMELOCK_SIGNALS)
        self.ctx.uses_twap = any_in(TWAP_SIGNALS)
        self.ctx.uses_chainlink = any_in(CHAINLINK_SIGNALS)
        self.ctx.has_emergency_pause = any_in(PAUSE_SIGNALS)
        self.ctx.has_audit_history = self.ctx.has_audit_history or any_in(AUDIT_SIGNALS)
        self.ctx.supports_rebasing = any_in(REBASING_SIGNALS)
        self.ctx.supports_fee_on_transfer = any_in(FOT_SIGNALS)
        self.ctx.only_standard_erc20 = any_in(STANDARD_ERC20_SIGNALS)

    # ── NatSpec reading ────────────────────────────────────────────────────

    def _read_source_natspec(self):
        """
        Parse NatSpec comments from all source files.
        Extracts per-function intent overrides.

        Handles:
          /// @dev permissionless by design
          /// @custom:security no reentrancy risk
          /** @notice ... */
        """
        source_extensions = {'.sol', '.vy', '.huff', '.rs', '.move', '.ts'}
        skip_dirs = {'node_modules', 'lib', 'out', 'cache', 'build', '__pycache__'}

        for root, dirs, files in os.walk(str(self.root)):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if Path(fname).suffix.lower() not in source_extensions:
                    continue
                fpath = Path(root) / fname
                content = self._safe_read(fpath)
                if content:
                    self._parse_natspec(content)

    def _parse_natspec(self, content: str):
        """
        Parse NatSpec and extract:
        1. Per-function suppression tags
        2. Global security signals
        3. @custom:security notes
        """
        # Extract @custom:security tags
        custom_security = re.findall(
            r'@custom:security\s+(.+?)(?:\n|$|\*/)',
            content, re.IGNORECASE
        )
        if custom_security:
            self.ctx.security_notes += ' ' + ' '.join(custom_security)

        # Find function-level NatSpec blocks
        # Pattern: natspec block immediately followed by function declaration
        natspec_fn_pattern = re.compile(
            r'((?:///[^\n]*\n|/\*\*.*?\*/\s*))'  # NatSpec block
            r'\s*function\s+(\w+)',               # Function declaration
            re.DOTALL | re.MULTILINE
        )

        for m in natspec_fn_pattern.finditer(content):
            natspec_block = m.group(1).lower()
            func_name = m.group(2)

            tags = set()
            for keyword, tag in NATSPEC_SUPPRESS_TAGS.items():
                if keyword in natspec_block:
                    tags.add(tag)

            if tags:
                existing = self.ctx.function_intent.get(func_name, set())
                self.ctx.function_intent[func_name] = existing | tags

        # Global signals from NatSpec across all files
        combined = content.lower()
        self._extract_signals_from_text(combined)

    # ── Import analysis ────────────────────────────────────────────────────

    def _read_source_imports(self):
        """
        Scan import statements across all Solidity files.
        SafeERC20, ReentrancyGuard, Ownable2Step etc. provide strong signals.
        """
        sol_files = list(self.root.rglob('*.sol'))
        # Limit to avoid scanning node_modules
        sol_files = [f for f in sol_files if 'node_modules' not in str(f)
                     and 'lib/' not in str(f) and 'out/' not in str(f)]

        combined_imports = ''
        for f in sol_files[:100]:  # Cap at 100 files
            text = self._safe_read(f)
            if text:
                # Extract only import lines + top-level declarations
                import_section = '\n'.join(
                    line for line in text.splitlines()[:50]  # First 50 lines
                    if 'import' in line.lower() or 'pragma' in line.lower()
                    or 'using' in line.lower()
                )
                combined_imports += import_section + '\n'

                # Check for upgradeable
                if re.search(r'(Initializable|UUPSUpgradeable|TransparentUpgradeable)', text):
                    self.ctx.is_upgradeable = True

                # Check for ReentrancyGuard
                if re.search(r'ReentrancyGuard|nonReentrant', text):
                    self.ctx.uses_reentrancy_guard = True

        combined_lower = combined_imports.lower()
        if 'safeerc20' in combined_lower:
            self.ctx.uses_safeERC20 = True
        if 'timelockcontroller' in combined_lower or 'timelock' in combined_lower:
            self.ctx.uses_timelock = True
        if 'chainlink' in combined_lower or 'aggregatorv3' in combined_lower:
            self.ctx.uses_chainlink = True

    # ── Protocol type detection ────────────────────────────────────────────

    def _detect_protocol_type(self):
        """Determine the primary protocol type from all gathered text."""
        scores = {ptype: 0 for ptype in PROTOCOL_TYPE_SIGNALS}

        combined = (
            self.ctx.readme_content + ' ' +
            self.ctx.description + ' ' +
            self.ctx.protocol_name.lower()
        )

        for ptype, signals in PROTOCOL_TYPE_SIGNALS.items():
            for signal in signals:
                if signal in combined:
                    scores[ptype] += 1

        best = max(scores, key=scores.get)
        if scores[best] > 0:
            self.ctx.protocol_type = best

    # ── Utility ───────────────────────────────────────────────────────────

    @staticmethod
    def _safe_read(path: Path) -> str:
        try:
            return path.read_text(encoding='utf-8', errors='replace')
        except Exception:
            return ''


def build_protocol_context(project_root: str) -> ProtocolContext:
    """Entry point — build ProtocolContext from a project root directory."""
    try:
        reader = DocReader(project_root)
        return reader.build()
    except Exception:
        # Never crash the scan due to doc reading
        return ProtocolContext()
