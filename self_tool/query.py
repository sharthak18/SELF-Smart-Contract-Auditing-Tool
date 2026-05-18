"""
SELF — Query DSL (Glider-inspired, runs 100% locally)
Allows auditors to write custom vulnerability queries in plain Python.

Inspired by: Hexens Glider, Semgrep, CodeQL
No cloud. No API key. Runs on your machine.

Usage in a custom detector::

    from self_tool.query import Q

    def detect(file_ctx):
        return (
            Q(file_ctx)
            .functions(visibility='external')
            .has_pattern(r'[.]call\\s*[{]')
            .not_has_pattern(r'nonReentrant')
            .not_has_pattern(r'bool\\s+\\w+\\s*,')
            .as_issues(
                id='CUSTOM-001',
                title='Unchecked external call',
                severity='HIGH',
            )
        )
"""
import re
from typing import List, Optional, Callable
from self_tool.core.issue import Issue, Severity, Confidence
from self_tool.core.scanner import FileContext


class FunctionContext:
    """Represents a single function extracted from source."""
    def __init__(self, name: str, body: str, full_sig: str, line: int,
                 visibility: str, mutability: str, modifiers: List[str]):
        self.name = name
        self.body = body
        self.full_sig = full_sig
        self.line = line
        self.visibility = visibility
        self.mutability = mutability
        self.modifiers = modifiers

    def has_pattern(self, pattern: str) -> bool:
        return bool(re.search(pattern, self.body + self.full_sig, re.MULTILINE))

    def not_has_pattern(self, pattern: str) -> bool:
        return not self.has_pattern(pattern)


class QueryResult:
    """Chainable query result."""
    def __init__(self, file_ctx: FileContext, functions: List[FunctionContext]):
        self._file_ctx = file_ctx
        self._functions = functions
        self._file_patterns: List[str] = []
        self._file_not_patterns: List[str] = []

    # ── File-level filters ─────────────────────────────────────────────────

    def file_has(self, pattern: str) -> 'QueryResult':
        """Keep result only if the file contains this pattern."""
        if not re.search(pattern, self._file_ctx.content, re.IGNORECASE):
            self._functions = []
        return self

    def file_not_has(self, pattern: str) -> 'QueryResult':
        """Keep result only if the file does NOT contain this pattern."""
        if re.search(pattern, self._file_ctx.content, re.IGNORECASE):
            self._functions = []
        return self

    # ── Function-level filters ─────────────────────────────────────────────

    def has_pattern(self, pattern: str) -> 'QueryResult':
        """Keep only functions whose body+sig matches pattern."""
        self._functions = [f for f in self._functions if f.has_pattern(pattern)]
        return self

    def not_has_pattern(self, pattern: str) -> 'QueryResult':
        """Keep only functions that do NOT match pattern."""
        self._functions = [f for f in self._functions if f.not_has_pattern(pattern)]
        return self

    def visibility(self, *vis: str) -> 'QueryResult':
        """Keep only functions with given visibility (public, external, internal, private)."""
        self._functions = [f for f in self._functions if f.visibility in vis]
        return self

    def mutability(self, *mut: str) -> 'QueryResult':
        """Keep only functions with given mutability (payable, view, pure, '')."""
        self._functions = [f for f in self._functions if f.mutability in mut]
        return self

    def has_modifier(self, *modifiers: str) -> 'QueryResult':
        """Keep only functions that have ALL listed modifiers."""
        def check(f):
            return all(any(m in mod for mod in f.modifiers) for m in modifiers)
        self._functions = [f for f in self._functions if check(f)]
        return self

    def not_has_modifier(self, *modifiers: str) -> 'QueryResult':
        """Keep only functions that have NONE of the listed modifiers."""
        self._functions = [f for f in self._functions if
                           not any(any(m in mod for mod in f.modifiers) for m in modifiers)]
        return self

    def name_matches(self, pattern: str) -> 'QueryResult':
        """Keep only functions whose name matches the regex."""
        self._functions = [f for f in self._functions if re.search(pattern, f.name)]
        return self

    def custom_filter(self, fn: Callable[[FunctionContext], bool]) -> 'QueryResult':
        """Apply an arbitrary Python function as a filter."""
        self._functions = [f for f in self._functions if fn(f)]
        return self

    # ── Output ─────────────────────────────────────────────────────────────

    def count(self) -> int:
        return len(self._functions)

    def matches(self) -> List[FunctionContext]:
        return self._functions

    def as_issues(
        self,
        id: str,
        title: str,
        severity: str,
        confidence: str,
        description: str,
        exploit_scenario: str,
        remediation: str,
        references: Optional[List[str]] = None,
    ) -> List[Issue]:
        """Convert query results to Issue objects."""
        issues = []
        for func in self._functions:
            # Format title and description with function name
            fmt = {'fname': func.name, 'line': func.line}
            issues.append(Issue(
                id=id,
                title=title.format(**fmt),
                severity=severity,
                confidence=confidence,
                file=self._file_ctx.relative_path,
                line=func.line,
                snippet=self._file_ctx.get_snippet(func.line, context=4),
                description=description.format(**fmt),
                exploit_scenario=exploit_scenario.format(**fmt),
                remediation=remediation.format(**fmt),
                references=references or [],
                language=self._file_ctx.language,
            ))
        return issues


class Q:
    """
    SELF Query Builder — Glider-inspired local query DSL.

    Example::

        issues = (
            Q(file_ctx)
            .functions(visibility='external')
            .has_pattern(r'[.]call[{]')
            .not_has_pattern(r'bool\\s+\\w+')
            .as_issues(id='X-001', title='Unchecked call in {fname}', ...)
        )
    """

    def __init__(self, file_ctx: FileContext):
        self._file_ctx = file_ctx
        self._content = file_ctx.content

    def functions(self, visibility: Optional[str] = None) -> QueryResult:
        """Extract all functions from the file and return a QueryResult."""
        funcs = self._extract_functions()
        result = QueryResult(self._file_ctx, funcs)
        if visibility:
            result.visibility(visibility)
        return result

    def _extract_functions(self) -> List[FunctionContext]:
        """Parse all functions from source."""
        funcs = []
        content = self._content

        func_re = re.compile(
            r'function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*)\{',
            re.MULTILINE
        )
        vis_re = re.compile(r'\b(public|external|internal|private)\b')
        mut_re = re.compile(r'\b(payable|view|pure)\b')
        mod_re = re.compile(r'\b([a-z]\w+)\b')

        for m in func_re.finditer(content):
            fname = m.group(1)
            attrs = m.group(3) or ''
            line = content[:m.start()].count('\n') + 1

            vis_m = vis_re.search(attrs)
            visibility = vis_m.group(1) if vis_m else 'internal'

            mut_m = mut_re.search(attrs)
            mutability = mut_m.group(1) if mut_m else ''

            # Extract modifiers
            keywords = {'public','external','internal','private','payable','view','pure',
                       'returns','virtual','override','memory','storage','calldata'}
            modifiers = [w for w in mod_re.findall(attrs) if w not in keywords]

            # Extract body
            func_start = m.end()
            depth = 1; i = func_start
            while i < len(content) and depth > 0:
                if content[i] == '{': depth += 1
                elif content[i] == '}': depth -= 1
                i += 1
            body = content[func_start:i]

            funcs.append(FunctionContext(
                name=fname,
                body=body,
                full_sig=m.group(0),
                line=line,
                visibility=visibility,
                mutability=mutability,
                modifiers=modifiers,
            ))
        return funcs
