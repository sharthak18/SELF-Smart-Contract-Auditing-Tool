"""SELF — Fuzzing layer.

Stateless: each call is independent; hypothesis drives per-argument fuzzing.
Stateful: sequence of calls drawn from a weighted action menu, with shrinking.
"""
from self_tool.fuzzing.stateless import (
    FuzzTarget,
    Invariant,
    StatelessFuzzResult,
    StatelessFuzzEngine,
    fuzz_stateless,
)

# stateful is exposed lazily so the package can import even if only
# the stateless engine is needed.
try:
    from self_tool.fuzzing.stateful import (
        StatefulAction,
        StatefulFuzzResult,
        StatefulFuzzEngine,
        fuzz_stateful,
    )
    _HAS_STATEFUL = True
except ImportError:  # pragma: no cover
    _HAS_STATEFUL = False

__all__ = [
    "FuzzTarget",
    "Invariant",
    "StatelessFuzzResult",
    "StatelessFuzzEngine",
    "fuzz_stateless",
]
if _HAS_STATEFUL:
    __all__ += ["StatefulAction", "StatefulFuzzResult", "StatefulFuzzEngine", "fuzz_stateful"]