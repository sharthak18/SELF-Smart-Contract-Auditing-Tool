"""
SELF — Control Flow Graph (CFG) Builder
Constructs a lightweight CFG from Solidity function bodies.
Nodes represent basic blocks; edges represent control flow.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple


@dataclass
class BasicBlock:
    id: int
    statements: List[str] = field(default_factory=list)
    successors: List['BasicBlock'] = field(default_factory=list)
    predecessors: List['BasicBlock'] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False

    def __hash__(self):
        return hash(self.id)
    
    def __eq__(self, other):
        if not isinstance(other, BasicBlock):
            return False
        return self.id == other.id

    def add_statement(self, stmt: str):
        self.statements.append(stmt)

    def add_successor(self, block: 'BasicBlock'):
        if block not in self.successors:
            self.successors.append(block)
            block.predecessors.append(self)


class CFG:
    def __init__(self):
        self.nodes: Dict[int, BasicBlock] = {}
        self.entry: Optional[BasicBlock] = None
        self.exit: Optional[BasicBlock] = None
        self._next_id = 0

    def new_block(self) -> BasicBlock:
        block = BasicBlock(id=self._next_id)
        self.nodes[self._next_id] = block
        self._next_id += 1
        return block

    def paths_between(self, start: BasicBlock, end: BasicBlock, visited: Optional[Set[int]] = None) -> List[List[BasicBlock]]:
        if visited is None:
            visited = set()
            
        if start == end:
            return [[start]]
            
        visited.add(start.id)
        paths = []
        
        for succ in start.successors:
            if succ.id not in visited:
                sub_paths = self.paths_between(succ, end, visited.copy())
                for path in sub_paths:
                    paths.append([start] + path)
                    
        return paths

    def get_reachable_blocks(self, start: BasicBlock) -> Set[BasicBlock]:
        reachable = set()
        stack = [start]
        while stack:
            curr = stack.pop()
            if curr not in reachable:
                reachable.add(curr)
                stack.extend(curr.successors)
        return reachable


def build_cfg(function_body: str) -> CFG:
    """
    Build a heuristic CFG from a Solidity function body.
    This is a lightweight regex-based CFG builder designed for vulnerability detection.
    It splits blocks on control-flow keywords (if, else, for, while, return, require, revert).
    """
    cfg = CFG()
    cfg.entry = cfg.new_block()
    cfg.entry.is_entry = True
    cfg.exit = cfg.new_block()
    cfg.exit.is_exit = True

    # Tokenize statements semi-intelligently, preserving braces
    statements = []
    current_stmt = ""
    depth = 0
    i = 0
    
    while i < len(function_body):
        char = function_body[i]
        
        if char == '{':
            if current_stmt.strip():
                statements.append(current_stmt.strip() + " {")
                current_stmt = ""
            else:
                statements.append("{")
            depth += 1
        elif char == '}':
            if current_stmt.strip():
                statements.append(current_stmt.strip())
                current_stmt = ""
            statements.append("}")
            depth -= 1
        elif char == ';':
            current_stmt += ';'
            statements.append(current_stmt.strip())
            current_stmt = ""
        else:
            current_stmt += char
            
        i += 1
        
    if current_stmt.strip():
        statements.append(current_stmt.strip())

    current_block = cfg.entry
    block_stack = []  # For loops/ifs (parent_block, end_block_target)
    
    for stmt in statements:
        stmt_clean = stmt.strip()
        if not stmt_clean:
            continue
            
        if stmt_clean == '}':
            if block_stack:
                _, target_block = block_stack.pop()
                if current_block is not None:
                    current_block.add_successor(target_block)
                current_block = target_block
            continue

        if current_block is None:
            current_block = cfg.new_block()
            
        current_block.add_statement(stmt_clean)

        # Control flow splitters
        if stmt_clean.startswith('if') or stmt_clean.startswith('if '):
            # Split: true branch and false/merge branch
            true_block = cfg.new_block()
            merge_block = cfg.new_block()
            
            current_block.add_successor(true_block)
            current_block.add_successor(merge_block)  # Assuming no else for simple heuristic
            
            block_stack.append((current_block, merge_block))
            current_block = true_block
            
        elif stmt_clean.startswith('else'):
            # The previous 'if' merge block becomes the else block
            if block_stack:
                # We need to restructure slightly for if-else, but for this heuristic
                # we just point the previous block to merge and start a new merge
                parent_block, old_merge = block_stack.pop()
                
                new_merge = cfg.new_block()
                
                # If the current block doesn't return/revert, it goes to the new merge
                if not any(k in stmt_clean for k in ['return', 'revert', 'require(', 'assert(']):
                    current_block.add_successor(new_merge)
                    
                # The old merge (false branch of if) is now this else block
                block_stack.append((parent_block, new_merge))
                current_block = old_merge
                current_block.add_statement(stmt_clean)
                
        elif stmt_clean.startswith('for') or stmt_clean.startswith('while'):
            loop_body = cfg.new_block()
            after_loop = cfg.new_block()
            
            current_block.add_successor(loop_body)
            current_block.add_successor(after_loop)
            
            # Loop body can jump back to itself or to after_loop (break)
            loop_body.add_successor(loop_body)
            loop_body.add_successor(after_loop)
            
            block_stack.append((current_block, after_loop))
            current_block = loop_body
            
        elif any(k in stmt_clean for k in ['return', 'revert', 'throw']):
            current_block.add_successor(cfg.exit)
            current_block = None  # Dead code until next block target
            
        elif stmt_clean.startswith('require(') or stmt_clean.startswith('assert('):
            # Implicit branch: continue or revert(exit)
            current_block.add_successor(cfg.exit)
            
    if current_block is not None:
        current_block.add_successor(cfg.exit)

    return cfg
