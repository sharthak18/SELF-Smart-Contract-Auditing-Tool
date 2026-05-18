"""
SELF — Protocol Context
Holds all extracted intent signals from documentation and NatSpec.
Used by detectors and the LLM analyzer to reduce false positives.
"""
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional


@dataclass
class ProtocolContext:
    """
    Everything SELF knows about the protocol *before* running detectors.
    Built by DocReader from README, docs/, NatSpec, imports, etc.
    """

    # ── Protocol identity ──────────────────────────────────────────────────
    protocol_name: str = "Unknown Protocol"
    protocol_type: str = "unknown"       # amm, lending, bridge, staking, nft, governance, unknown
    description: str = ""

    # ── Security posture claims (from docs) ────────────────────────────────
    uses_multisig: bool = False          # Gnosis Safe / multisig mentioned
    uses_timelock: bool = False          # Timelock mentioned
    uses_twap: bool = False              # TWAP oracle mentioned
    uses_chainlink: bool = False         # Chainlink oracle mentioned
    uses_safeERC20: bool = False         # SafeERC20 imported
    uses_reentrancy_guard: bool = False  # ReentrancyGuard used
    is_upgradeable: bool = False         # Upgradeable proxy pattern
    is_permissioned: bool = False        # Access-controlled protocol
    has_emergency_pause: bool = False    # Emergency pause exists
    has_audit_history: bool = False      # Previous audits mentioned

    # ── Token assumptions (from docs) ──────────────────────────────────────
    supports_fee_on_transfer: bool = False
    supports_rebasing: bool = False
    only_standard_erc20: bool = False    # "Only standard ERC20" in docs

    # ── Per-function intent overrides (from NatSpec) ───────────────────────
    # Maps function_name → set of suppression tags
    function_intent: Dict[str, Set[str]] = field(default_factory=dict)
    # e.g. {"withdraw": {"permissionless", "no_deadline"}, "initialize": {"expected_public"}}

    # ── Raw doc content (for LLM context) ─────────────────────────────────
    readme_content: str = ""
    security_notes: str = ""             # SECURITY.md or @custom:security tags

    # ── Suppression rules built from above signals ─────────────────────────
    # Set of (detector_id, reason) tuples
    _suppressions: Dict[str, str] = field(default_factory=dict)

    def build_suppressions(self):
        """Derive suppression rules from signals. Call after all signals are set."""
        s = self._suppressions

        if self.uses_multisig and self.uses_timelock:
            s["SOL-MED-001"] = "Protocol documents Gnosis Safe multisig + timelock"
            s["SOL-CRIT-009"] = None  # don't suppress critical tx.origin

        elif self.uses_multisig:
            # Soften, don't suppress
            self._note("SOL-MED-001", "Centralization partially mitigated by multisig")

        if self.uses_twap or self.uses_chainlink:
            s["SOL-HIGH-001"] = "Protocol documents TWAP/Chainlink oracle usage"
            s["SOL-MED-004"] = "Protocol uses Chainlink — staleness likely handled"

        if self.uses_safeERC20:
            s["SOL-HIGH-008"] = "SafeERC20 imported — unchecked transfer suppressed"

        if self.uses_reentrancy_guard:
            s["SOL-CRIT-001"] = "ReentrancyGuard imported — likely used correctly"
            s["SOL-CRIT-002"] = "ReentrancyGuard imported"

        if self.only_standard_erc20:
            s["AMM-HIGH-003"] = "Protocol documents standard ERC20 only — FoT suppressed"

        if self.is_upgradeable:
            # Expected, downgrade to INFO
            self._note("SOL-CRIT-007", "Upgradeability is documented and expected")

        if self.has_emergency_pause:
            self._note("SOL-MED-001", "Emergency pause mechanism documented")

    def _note(self, detector_id: str, note: str):
        """Add a note (not a full suppression) for a detector."""
        self._suppressions[f"_note_{detector_id}"] = note

    def suppresses(self, detector_id: str) -> bool:
        """Return True if this finding should be suppressed."""
        return detector_id in self._suppressions

    def suppression_reason(self, detector_id: str) -> str:
        return self._suppressions.get(detector_id, "")

    def function_suppresses(self, func_name: str, tag: str) -> bool:
        """Return True if a specific function has a suppression tag."""
        return tag in self.function_intent.get(func_name, set())

    def get_llm_summary(self) -> str:
        """Short summary for LLM prompt context."""
        lines = [
            f"Protocol: {self.protocol_name}",
            f"Type: {self.protocol_type}",
            f"Uses multisig: {self.uses_multisig}",
            f"Uses timelock: {self.uses_timelock}",
            f"Oracle: {'TWAP' if self.uses_twap else 'Chainlink' if self.uses_chainlink else 'Unknown'}",
            f"Upgradeable: {self.is_upgradeable}",
            f"SafeERC20: {self.uses_safeERC20}",
            f"ReentrancyGuard: {self.uses_reentrancy_guard}",
        ]
        if self.description:
            lines.append(f"Description: {self.description[:300]}")
        if self.security_notes:
            lines.append(f"Security notes: {self.security_notes[:300]}")
        return "\n".join(lines)


# Singleton empty context (when no docs found)
EMPTY_CONTEXT = ProtocolContext()
