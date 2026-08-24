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
from typing import List, Optional, Sequence, Tuple

from self_tool.core.local_docs import (
    extract_pdf_text,
    extract_urls,
    list_prior_audit_files,
    summarize_refs,
)
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


# Map sponsor-declared known issues onto autonomous playbooks so the
# reasoner can keep them in mind instead of re-reporting accepted risk.
KNOWN_ISSUE_PLAYBOOKS: List[Tuple[str, List[str]]] = [
    (r"first.?deposit|donation.?inflation|virtual.?share|yieldbuffer|donate assets equal",
     ["AV-FIRST-DEPOSITOR"]),
    (r"storage gap|storage collision",
     ["AV-STORAGE-COLLISION"]),
    (r"fee-?on-?transfer|fees on transfer|rebasing|does not support (fot|fee)|no fee-on-transfer",
     ["AV-FEE-ON-TRANSFER"]),
    (r"sequencer|l2 downtime",
     ["AV-L2-SEQUENCER"]),
    (r"create2|metamorphic",
     ["AV-CREATE2-METAMORPHIC"]),
    (r"misconfigured oracle|oracle(s)? (are )?trusted|no fallback oracle|"
     r"chainlink reports a wrong price|spot (amm )?oracle|"
     r"oracles and normalization|choose oracles and oracle normalization",
     ["AV-ORACLE-SPOT"]),
    (r"outdated answers|stale (price|oracle|answer)|heartbeat",
     ["AV-L2-SEQUENCER"]),
    (r"rounding error|precision loss|due to rounding",
     ["AV-ROUNDING-DIRECTION"]),
    (r"centralization risk|admin is trusted|owner is trusted|trusted role",
     ["AV-GOVERNANCE-FLASH"]),
]

CONTEST_DOC_NAMES = (
    "README.md", "README-sponsor.md", "README.rst", "README.txt", "README",
    "WHITEPAPER.md", "whitepaper.md",
    "SECURITY.md", "security.md",
    "ARCHITECTURE.md", "architecture.md",
    "DESIGN.md", "design.md",
    "scope.txt", "out_of_scope.txt",
)


def resolve_docs_root(project_root: str) -> Path:
    """Walk up so `self autonomous contracts` prefers the contest README over a nested package README."""
    start = Path(project_root).resolve()
    cur = start if start.is_dir() else start.parent
    ranked = []
    for _ in range(6):
        score = 0
        if (cur / "scope.txt").is_file() or (cur / "out_of_scope.txt").is_file():
            score += 6
        if (cur / "README-sponsor.md").is_file():
            score += 3
        readme = cur / "README.md"
        if readme.is_file():
            score += 1
            try:
                head = readme.read_text(encoding="utf-8", errors="replace")[:12000].lower()
            except OSError:
                head = ""
            if any(token in head for token in (
                "known issue", "publicly known", "trusted role", "files in scope",
                "out of scope", "warden",
            )):
                score += 6
        if score:
            ranked.append((score, len(str(cur)), cur))
        if cur.parent == cur:
            break
        cur = cur.parent
    if not ranked:
        return start
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return ranked[0][2]


class DocReader:
    """Reads project documentation and source NatSpec to build a ProtocolContext."""

    def __init__(self, project_root: str):
        requested = Path(project_root).resolve()
        self.root = resolve_docs_root(str(requested))
        self.ctx = ProtocolContext()
        self.ctx.docs_root = str(self.root)

    def build(self) -> ProtocolContext:
        """Full pipeline: read all docs → extract signals → return context."""
        self._read_doc_files()
        self._read_source_natspec()
        self._read_source_imports()
        self._detect_protocol_type()
        self._extract_contest_brief()
        self.ctx.build_suppressions()
        return self.ctx

    # ── Documentation reading ──────────────────────────────────────────────

    def _read_doc_files(self):
        """Read README, docs/, WHITEPAPER, SECURITY, audit reports."""
        doc_candidates = list(CONTEST_DOC_NAMES)

        all_text = []
        security_text = []
        self._doc_blobs: List[Tuple[str, str]] = []

        for fname in doc_candidates:
            fpath = self.root / fname
            if fpath.exists():
                text = self._safe_read(fpath)
                all_text.append(text)
                self._doc_blobs.append((fname, text))
                if 'SECURITY' in fname.upper() or 'security' in fname.lower():
                    security_text.append(text)

        # docs/ directory
        for docs_dir in ['docs', 'documentation', 'doc']:
            docs_path = self.root / docs_dir
            if docs_path.is_dir():
                for md_file in docs_path.rglob('*.md'):
                    text = self._safe_read(md_file)
                    all_text.append(text)

        # audits/ + reports/: markdown, html, and PDF text
        for audit_dir in ['audits', 'audit', 'reports', 'security']:
            audit_path = self.root / audit_dir
            if audit_path.is_dir():
                for audit_file in sorted(audit_path.rglob('*')):
                    if not audit_file.is_file():
                        continue
                    suffix = audit_file.suffix.lower()
                    if suffix == '.pdf':
                        try:
                            extracted = extract_pdf_text(audit_file.read_bytes())
                        except OSError:
                            extracted = ""
                        if extracted:
                            all_text.append(extracted)
                            self._doc_blobs.append((str(audit_file.relative_to(self.root)), extracted))
                            self.ctx.has_audit_history = True
                    elif suffix in {'.md', '.txt', '.html'}:
                        extracted = self._safe_read(audit_file)
                        all_text.append(extracted)
                        self._doc_blobs.append((str(audit_file.relative_to(self.root)), extracted))
                        self.ctx.has_audit_history = True

        # Inventory links and local prior-audit files (offline acknowledge).
        joined = "\n\n".join(all_text)
        for url in extract_urls(joined):
            if url not in self.ctx.referenced_urls:
                self.ctx.referenced_urls.append(url)
        self.ctx.local_audit_files = list_prior_audit_files(self.root)
        if self.ctx.local_audit_files:
            self.ctx.has_audit_history = True

        combined = ' '.join(all_text).lower()
        self.ctx.readme_content = combined[:20000]
        self.ctx.security_notes = ' '.join(security_text)[:4000]
        if all_text:
            self.ctx.docs_read = True

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
        sol_files = [f for f in self.root.rglob('*.sol') if f.is_file()]
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

    def _extract_contest_brief(self):
        """Parse C4/Sherlock-style README sections and scope.txt files."""
        blobs = list(getattr(self, "_doc_blobs", []) or [])
        full = "\n\n".join(text for _, text in blobs)
        if not full.strip():
            return

        known_section = "\n\n".join(_all_sections(full, (
            "automated findings", "publicly known issues", "publicly known issue",
            "known issues", "known issue", "known limitations",
        )))
        for bullet in _known_issue_items(known_section):
            if _is_boilerplate_known_issue(bullet):
                continue
            if bullet not in self.ctx.known_issues:
                self.ctx.known_issues.append(bullet[:400])

        trust_section = _first_section(full, (
            "all trusted roles in the protocol", "trusted roles",
        ))
        for role, note in _role_rows(trust_section):
            if role not in self.ctx.trusted_roles:
                self.ctx.trusted_roles.append(role)
            if note:
                self.ctx.trusted_role_notes.append(f"{role}: {note[:240]}")
        for match in re.finditer(
            r"roles? in the protocol\s*:\s*(.+)", full, re.IGNORECASE,
        ):
            blob = match.group(1)
            for piece in re.split(r",|;", blob):
                name = piece.split("(")[0].split("which")[0].strip(" .)")
                if _plausible_role(name) and name not in self.ctx.trusted_roles:
                    self.ctx.trusted_roles.append(name)

        oos_section = _first_section(full, (
            "files out of scope", "out of scope",
        ))
        for path in _paths_from_text(oos_section):
            _append_unique(self.ctx.out_of_scope_files, path)
        in_section = _first_section(full, (
            "files in scope",
        ))
        for path in _paths_from_text(in_section):
            _append_unique(self.ctx.in_scope_files, path)

        for name, blob in blobs:
            lowered = name.lower()
            if lowered.endswith("out_of_scope.txt"):
                for path in _paths_from_text(blob):
                    _append_unique(self.ctx.out_of_scope_files, path)
            elif lowered.endswith("scope.txt") and "out_of_scope" not in lowered:
                for path in _paths_from_text(blob):
                    _append_unique(self.ctx.in_scope_files, path)

        accepted = []
        hay = "\n".join(self.ctx.known_issues).lower() + "\n" + (known_section or "").lower()
        extra = _first_section(full, ("additional context", "assumptions"))
        if re.search(
            r"fee-on-transfer or rebasing tokens are not supported|"
            r"does not support rebasing/fee-on-transfer",
            extra, re.I,
        ):
            hay += "\nfee-on-transfer tokens are not supported"
        for pattern, playbooks in KNOWN_ISSUE_PLAYBOOKS:
            if re.search(pattern, hay, re.IGNORECASE):
                for playbook in playbooks:
                    if playbook not in accepted:
                        accepted.append(playbook)
        self.ctx.accepted_playbooks = accepted

    # ── Utility ───────────────────────────────────────────────────────────

    @staticmethod
    def _safe_read(path: Path) -> str:
        if not path.is_file():
            return ""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""


def _first_section(text: str, titles):
    sections = _all_sections(text, titles)
    return sections[0] if sections else ""


def _all_sections(text: str, titles):
    heading = re.compile(r"^(#{1,4})\s+(.+?)\s*$", re.MULTILINE)
    matches = list(heading.finditer(text))
    found = []
    for index, match in enumerate(matches):
        title = match.group(2).strip().lower()
        if not any(needle in title for needle in titles):
            continue
        level = len(match.group(1))
        start = match.end()
        end = len(text)
        for later in matches[index + 1:]:
            if len(later.group(1)) <= level:
                end = later.start()
                break
        found.append(text[start:end])
    return found


def _bullets(section: str):
    items = []
    for raw in (section or "").splitlines():
        line = raw.strip()
        if line.startswith(("-", "*", "+")):
            text = line.lstrip("-*+ ").strip()
            if text:
                items.append(text)
    return items


def _is_boilerplate_known_issue(text: str) -> bool:
    lower = text.lower()
    if "4naly3er" in lower or "bot-report" in lower:
        return True
    if "ineligible for awards" in lower:
        return True
    if lower.startswith("http") or lower.startswith("[here]"):
        return True
    return False


def _role_rows(section: str):
    rows = []
    for raw in (section or "").splitlines():
        line = raw.strip()
        if line.startswith("|"):
            cols = [col.strip().strip("`*") for col in line.strip("|").split("|")]
            if not cols:
                continue
            name = cols[0]
            if not _plausible_role(name):
                continue
            note = cols[1] if len(cols) > 1 else ""
            rows.append((name, note))
            continue
        if line.startswith(("-", "*", "+")):
            text = line.lstrip("-*+ ").strip()
            name = text.split(":")[0].split("—")[0].strip()
            if _plausible_role(name):
                rows.append((name, text))
    return rows


def _plausible_role(name: str) -> bool:
    if not name or set(name) <= set("-: "):
        return False
    if name.lower() in {"role", "name", "actor", "file", "description"}:
        return False
    if len(name) > 48 or name.endswith("?"):
        return False
    if name.lower().startswith((
        "how ", "what ", "is ", "does ", "if ", "the ", "any ", "only ",
        "check ", "please ", "total ",
    )):
        return False
    if "http" in name.lower() or "`" in name:
        return False
    if "_" in name and name.replace("_", "").isalnum():
        return True
    words = name.replace("_", " ").split()
    if len(words) > 3:
        return False
    return True


def _known_issue_items(section: str):
    items = _bullets(section)
    if items:
        return items
    collected = []
    current = []
    for raw in (section or "").splitlines():
        line = raw.strip()
        if line.startswith("###"):
            if current:
                collected.append(" ".join(current))
            current = [line.lstrip("# ").strip()]
        elif line.startswith("#"):
            if current:
                collected.append(" ".join(current))
            current = []
        elif line:
            if current:
                current.append(line)
            elif len(line) > 40:
                current = [line]
    if current:
        collected.append(" ".join(current))
    return [item[:400] for item in collected if item]


def _paths_from_text(text: str):
    found = []
    for raw in (text or "").splitlines():
        line = raw.strip().strip("|").strip()
        if not line or line.startswith("#") or set(line) <= set("-: |"):
            continue
        cell = line.split("|")[0].strip().strip("`*")
        cell = re.sub(r"^\[.*?\]\((.*?)\)$", r"\1", cell)
        cell = cell.split()[0] if cell else ""
        cell = cell.strip(".,;()[]")
        if _looks_like_source_path(cell):
            _append_unique(found, cell.lstrip("./"))
    for match in re.finditer(r"(?:\./)?[\w./-]+\.(?:sol|vy|rs|move|cairo)", text or ""):
        _append_unique(found, match.group(0))
    return found


def _looks_like_source_path(value: str) -> bool:
    if not value or " " in value or len(value) > 240:
        return False
    lower = value.lower()
    return lower.endswith((".sol", ".vy", ".rs", ".move", ".cairo")) or "/" in value


def _append_unique(bucket, value: str) -> None:
    value = value.strip()
    if value and value not in bucket:
        bucket.append(value)


def path_is_listed(path: str, listed: Sequence[str]) -> bool:
    """True if a scanned relative path matches a scope.txt / out_of_scope entry."""
    cand = _norm_doc_path(path)
    if not cand:
        return False
    cand_parts = [part for part in cand.split("/") if part]
    for raw in listed or []:
        item = _norm_doc_path(raw)
        if not item:
            continue
        item_parts = [part for part in item.split("/") if part]
        if not item_parts:
            continue
        if cand == item or cand.endswith("/" + item) or item.endswith("/" + cand):
            return True
        if len(item_parts) >= 2 and cand_parts[-len(item_parts):] == item_parts:
            return True
        if item_parts[-1] == cand_parts[-1] and any(
            marker in item for marker in ("mock", "interface", "test/", "script/", "lib/")
        ):
            return True
    return False


def _norm_doc_path(path: str) -> str:
    return (path or "").replace("\\", "/").lstrip("./").strip().lower()


def build_protocol_context(project_root: str) -> ProtocolContext:
    """Entry point — build ProtocolContext from a project root directory."""
    reader = DocReader(project_root)
    return reader.build()


def merge_brief_from_text(ctx: ProtocolContext, text: str) -> None:
    """Fold extra documentation (fetched pages, PDFs) into an existing brief.

    Known-issue / role / OOS extraction is additive. Accepted playbooks are
    only remapped from *this* text when it looks like a sponsor Known Issues
    section — random blog posts do not silently accept risk.
    """
    if not (text or "").strip() or ctx is None:
        return
    from self_tool.core.local_docs import extract_urls as _urls

    for url in _urls(text):
        if url not in ctx.referenced_urls:
            ctx.referenced_urls.append(url)

    known_section = "\n\n".join(_all_sections(text, (
        "automated findings", "publicly known issues", "publicly known issue",
        "known issues", "known issue", "known limitations",
    )))
    for bullet in _known_issue_items(known_section):
        if _is_boilerplate_known_issue(bullet):
            continue
        if bullet not in ctx.known_issues:
            ctx.known_issues.append(bullet[:400])

    trust_section = _first_section(text, (
        "all trusted roles in the protocol", "trusted roles",
    ))
    for role, note in _role_rows(trust_section):
        if role not in ctx.trusted_roles:
            ctx.trusted_roles.append(role)
        if note:
            ctx.trusted_role_notes.append(f"{role}: {note[:240]}")

    oos_section = _first_section(text, ("files out of scope", "out of scope"))
    for path in _paths_from_text(oos_section):
        _append_unique(ctx.out_of_scope_files, path)

    if known_section.strip():
        hay = "\n".join(ctx.known_issues).lower() + "\n" + known_section.lower()
        for pattern, playbooks in KNOWN_ISSUE_PLAYBOOKS:
            if re.search(pattern, hay, re.IGNORECASE):
                for playbook in playbooks:
                    if playbook not in ctx.accepted_playbooks:
                        ctx.accepted_playbooks.append(playbook)

    ctx.has_audit_history = ctx.has_audit_history or bool(
        re.search(r"audit report|audited by|security review", text, re.I)
    )
    if not ctx.docs_read and text.strip():
        ctx.docs_read = True
