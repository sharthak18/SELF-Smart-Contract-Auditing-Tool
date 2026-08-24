"""Extract language-agnostic contract and function facts from every parser."""

from __future__ import annotations

import re
from typing import Iterable, List, Sequence

from self_tool.autonomous.models import ExtractedContract, ExtractedFunction
from self_tool.core.scanner import FileContext


PRIVILEGED_NAME_RE = re.compile(
    r"(owner|admin|upgrade|initialize|init|pause|unpause|set[A-Z]|mint|burn|"
    r"sweep|rescue|grantrole|revokerole|transferownership|selfdestruct|destroy|"
    r"liquidate|seize|processmessage|completeTransfer)",
    re.IGNORECASE,
)
WRITE_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:=|\+=|-=|\*=|/=|\+\+|--)|"
    r"\bdelete\s+([A-Za-z_]\w*)|"
    r"\b([A-Za-z_]\w*)\s*\.\s*(?:push|pop|insert|remove)\s*\("
)
CALL_RE = re.compile(
    r"\.(call|delegatecall|staticcall|transfer|send|transferFrom|safeTransfer|"
    r"safeTransferFrom|approve|mint|burn|invoke|invoke_signed|raw_call)\s*(?:\{|\()"
)
SOL_FUNC_RE = re.compile(
    r"(?:#\[(?:external(?:\([^)]*\))?|view|onchain)[^\]]*\]\s*)*"
    r"(?:fn|func|def|function)\s+(\w+)\s*\(([^)]*)\)",
    re.MULTILINE,
)


def extract_contracts(files: Sequence[FileContext]) -> List[ExtractedContract]:
    contracts: List[ExtractedContract] = []
    for file_ctx in files:
        if file_ctx.language == "solidity":
            contracts.extend(_from_solidity(file_ctx))
        elif file_ctx.language == "vyper":
            contracts.extend(_from_vyper(file_ctx))
        elif file_ctx.language == "rust":
            contracts.extend(_from_rust(file_ctx))
        elif file_ctx.language == "move":
            contracts.extend(_from_generic(file_ctx, kind="module"))
        elif file_ctx.language == "huff":
            contracts.extend(_from_generic(file_ctx, kind="bytecode"))
        elif file_ctx.language in {"cairo", "sway", "tact"}:
            contracts.extend(_from_generic(file_ctx, kind="contract"))
        else:
            contracts.extend(_from_generic(file_ctx, kind="file"))
    contracts.sort(key=lambda item: (item.file, item.line, item.name))
    return contracts


def _from_solidity(file_ctx: FileContext) -> List[ExtractedContract]:
    from self_tool.parsers.solidity_parser import parse_solidity

    info = parse_solidity(file_ctx)
    out: List[ExtractedContract] = []
    for contract in info.contracts:
        functions = []
        state_names = [var.name for var in contract.state_vars]
        for func in contract.functions:
            functions.append(_function(
                language="solidity",
                file=file_ctx.relative_path,
                contract=contract.name,
                name=func.name,
                line=func.line,
                visibility=func.visibility,
                mutability=func.mutability,
                modifiers=list(func.modifiers),
                params=func.params,
                body=func.body,
                state_names=state_names,
            ))
        out.append(ExtractedContract(
            language="solidity",
            file=file_ctx.relative_path,
            name=contract.name,
            kind=contract.kind,
            line=contract.line,
            inherits=list(contract.inherits),
            functions=functions,
            state_vars=state_names,
            role_guess=guess_role(contract.name, contract.inherits, file_ctx.content),
        ))
    return out


def _from_vyper(file_ctx: FileContext) -> List[ExtractedContract]:
    from self_tool.parsers.vyper_parser import parse_vyper

    info = parse_vyper(file_ctx)
    out: List[ExtractedContract] = []
    for contract in info.contracts:
        state_names = [var.name for var in contract.state_vars]
        functions = []
        for func in contract.functions:
            functions.append(_function(
                language="vyper",
                file=file_ctx.relative_path,
                contract=contract.name,
                name=func.name,
                line=func.line,
                visibility=func.visibility,
                mutability=func.mutability,
                modifiers=list(func.decorators),
                params=func.params,
                body=func.body,
                state_names=state_names,
            ))
        out.append(ExtractedContract(
            language="vyper",
            file=file_ctx.relative_path,
            name=contract.name,
            kind="contract",
            line=1,
            inherits=list(contract.interfaces),
            functions=functions,
            state_vars=state_names,
            role_guess=guess_role(contract.name, contract.interfaces, file_ctx.content),
        ))
    return out


def _from_rust(file_ctx: FileContext) -> List[ExtractedContract]:
    from self_tool.parsers.rust_parser import parse_rust

    prog = parse_rust(file_ctx)
    functions = []
    for instr in prog.instructions:
        body = instr.body
        functions.append(_function(
            language="rust",
            file=file_ctx.relative_path,
            contract=prog.program_mod or prog.path,
            name=instr.name,
            line=instr.line,
            visibility="public",
            mutability="",
            modifiers=[],
            params=", ".join(f"{n}: {t}" for n, t in instr.params),
            body=body,
            state_names=[],
        ))
    name = prog.program_mod or file_ctx.relative_path
    return [ExtractedContract(
        language="rust",
        file=file_ctx.relative_path,
        name=name,
        kind="anchor" if prog.is_anchor else "solana",
        line=1,
        inherits=[],
        functions=functions,
        state_vars=sorted(prog.accounts_structs),
        role_guess=guess_role(name, [], file_ctx.content),
    )]


_GENERIC_FUNC_RE = {
    "move": re.compile(r"(?:public\s+(?:entry\s+)?)?fun\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE),
    "cairo": re.compile(r"fn\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE),
    "sway": re.compile(r"fn\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE),
    "tact": re.compile(r"(?:receive|fun|get)\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE),
    "huff": re.compile(r"#define\s+macro\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE),
}


def _from_generic(file_ctx: FileContext, kind: str) -> List[ExtractedContract]:
    pattern = _GENERIC_FUNC_RE.get(file_ctx.language, SOL_FUNC_RE)
    functions: List[ExtractedFunction] = []
    for match in pattern.finditer(file_ctx.content):
        name = match.group(1)
        params = match.group(2) if match.lastindex and match.lastindex >= 2 else ""
        line = file_ctx.content[:match.start()].count("\n") + 1
        body = _slice_body(file_ctx.content, match.end())
        functions.append(_function(
            language=file_ctx.language,
            file=file_ctx.relative_path,
            contract=file_ctx.relative_path,
            name=name,
            line=line,
            visibility="public",
            mutability="",
            modifiers=[],
            params=params,
            body=body,
            state_names=[],
        ))
    return [ExtractedContract(
        language=file_ctx.language,
        file=file_ctx.relative_path,
        name=PathStem(file_ctx.relative_path),
        kind=kind,
        line=1,
        functions=functions,
        role_guess=guess_role(PathStem(file_ctx.relative_path), [], file_ctx.content),
    )]


def PathStem(path: str) -> str:
    name = path.replace("\\", "/").split("/")[-1]
    if "." in name:
        return name.rsplit(".", 1)[0]
    return name


def _slice_body(content: str, start: int, limit: int = 2500) -> str:
    return content[start:start + limit]


def _function(
    *,
    language: str,
    file: str,
    contract: str,
    name: str,
    line: int,
    visibility: str,
    mutability: str,
    modifiers: List[str],
    params: str,
    body: str,
    state_names: Sequence[str],
) -> ExtractedFunction:
    writes = []
    if state_names:
        for var in state_names:
            if re.search(
                rf"\b{re.escape(var)}\b(?:\s*\[[^\]]+\])*\s*(?:=|\+=|-=|\*=|/=|\+\+|--)",
                body,
            ):
                writes.append(var)
    else:
        for match in WRITE_RE.finditer(body):
            name_hit = next((group for group in match.groups() if group), None)
            if name_hit and name_hit not in writes:
                writes.append(name_hit)
    calls = sorted({match.group(1) for match in CALL_RE.finditer(body)})
    return ExtractedFunction(
        language=language,
        file=file,
        contract=contract,
        name=name,
        line=line,
        visibility=visibility or "",
        mutability=mutability or "",
        modifiers=list(modifiers),
        params=params or "",
        body=body or "",
        state_writes=writes,
        external_calls=calls,
        is_privileged_name=bool(PRIVILEGED_NAME_RE.search(name)),
    )


def guess_role(name: str, inherits: Iterable[str], content: str) -> str:
    blob = " ".join([name, " ".join(inherits), content[:2000]]).lower()
    checks = (
        ("oracle", ("oracle", "aggregatorv3", "twap", "pricefeed")),
        ("bridge", ("wormhole", "layerzero", "lzreceive", "processmessage", "completetransfer", "mailbox")),
        ("governor", ("governor", "timelock", "proposal", "dao")),
        ("pool", ("pool", "pair", "amm", "swap", "reserves")),
        ("vault", ("vault", "erc4626", "strategy", "share")),
        ("lending", ("lending", "borrow", "collateral", "liquidate", "ctoken")),
        ("staking", ("stak", "farm", "reward", "gauge")),
        ("token", ("erc20", "erc721", "mint", "burn", "allowance")),
        ("proxy", ("proxy", "upgradeable", "erc1967", "uups")),
        ("router", ("router", "zap", "aggregator")),
    )
    for role, needles in checks:
        if any(needle in blob for needle in needles):
            return role
    return "module"


def combined_source(files: Sequence[FileContext]) -> str:
    return "\n".join(ctx.content for ctx in files)
