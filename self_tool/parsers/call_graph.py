"""
SELF — Call Graph Builder
Builds a static call graph for intra-contract function invocations.
Tracks external entry points to internal implementations.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

from self_tool.parsers.solidity_parser import SolContract, SolFunction


@dataclass
class CallGraphNode:
    function: SolFunction
    calls: Set['CallGraphNode'] = field(default_factory=set)
    called_by: Set['CallGraphNode'] = field(default_factory=set)

    def __hash__(self):
        return hash(self.function.name)

    def __eq__(self, other):
        if not isinstance(other, CallGraphNode):
            return False
        return self.function.name == other.function.name


class CallGraph:
    def __init__(self, contract: SolContract):
        self.contract = contract
        self.nodes: Dict[str, CallGraphNode] = {}
        self._build()

    def _build(self):
        # Initialize nodes
        for func in self.contract.functions:
            self.nodes[func.name] = CallGraphNode(function=func)

        # Basic static regex resolution
        # This resolves direct internal calls: `_doSomething(msg.sender)`
        for func in self.contract.functions:
            caller_node = self.nodes[func.name]
            body = func.body
            
            # Find potential function calls in the body
            # Matches words followed by (, ignoring keywords
            call_matches = re.finditer(r'\b([A-Za-z_]\w*)\s*\(', body)
            
            for match in call_matches:
                callee_name = match.group(1)
                
                # Exclude keywords and built-ins
                if callee_name in {"require", "assert", "revert", "keccak256", "abi", "type"}:
                    continue
                    
                if callee_name in self.nodes:
                    callee_node = self.nodes[callee_name]
                    caller_node.calls.add(callee_node)
                    callee_node.called_by.add(caller_node)

    def get_reachable_from(self, entry_func_name: str) -> Set[CallGraphNode]:
        """Get all functions reachable from an entry point."""
        if entry_func_name not in self.nodes:
            return set()
            
        reachable = set()
        stack = [self.nodes[entry_func_name]]
        
        while stack:
            curr = stack.pop()
            if curr not in reachable:
                reachable.add(curr)
                stack.extend(curr.calls)
                
        return reachable

    def get_entry_points(self) -> List[CallGraphNode]:
        """Return all public/external functions."""
        return [
            node for node in self.nodes.values()
            if node.function.visibility in {"public", "external"}
        ]
