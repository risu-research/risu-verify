from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any, Dict, List, Sequence, Set, Tuple

MAX_ROUND0_FILES = 4
MAX_EXPANSION_ROUNDS = 2
MAX_TOTAL_FILES = 32
SUPPORTED_EXTENSIONS = (".py", ".go", ".md", ".yaml", ".yml", ".json", ".txt")
EXCLUDE_FRAGMENTS = ("vendor/", "third_party/", "node_modules/", "translations/")

def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def tokens(value: str) -> Tuple[str, ...]:
    return tuple(re.findall(r"[a-z0-9]+", value.lower()))

def compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())

def eligible_path(path: str) -> bool:
    low = path.lower()
    if any(x in low for x in EXCLUDE_FRAGMENTS):
        return False
    return low.endswith(SUPPORTED_EXTENSIONS)

def operation_features(path: str, screened_operation: str, surface_arguments: Sequence[str]) -> Dict[str, int]:
    p_tokens = set(tokens(path))
    stem = PurePosixPath(path.lower()).stem
    op_tokens = list(tokens(screened_operation))
    verb = next((t for t in op_tokens[1:] if not t.startswith("-")), op_tokens[-1] if op_tokens else "")
    arg_compacts = [compact(a) for a in surface_arguments if a]
    p_compact = compact(path)
    exact_verb = int(bool(verb) and (stem == verb or verb in p_tokens))
    op_overlap = len(set(op_tokens) & p_tokens)
    arg_hits = sum(1 for a in arg_compacts if a and a in p_compact)
    commandish = int(any(x in p_tokens for x in {"cmd", "command", "commands", "cli"}))
    return {
        "exact_verb": exact_verb,
        "argument_hits": arg_hits,
        "operation_token_overlap": op_overlap,
        "commandish": commandish,
    }

def _positive(f: Dict[str, int]) -> bool:
    return bool(f["exact_verb"] or f["argument_hits"] or f["operation_token_overlap"] >= 2)

def round0_select(tree_paths: Sequence[str], screened_operation: str, surface_arguments: Sequence[str]) -> List[Dict[str, Any]]:
    rows=[]
    for path in tree_paths:
        if not eligible_path(path):
            continue
        f=operation_features(path, screened_operation, surface_arguments)
        if not _positive(f):
            continue
        rows.append({"path":path,"features":f})
    rows.sort(key=lambda r:(
        -r["features"]["exact_verb"],
        -r["features"]["argument_hits"],
        -r["features"]["operation_token_overlap"],
        -r["features"]["commandish"],
        r["path"],
    ))
    return [{"round":0,"rank":i+1,**r} for i,r in enumerate(rows[:MAX_ROUND0_FILES])]

_IMPORT_RE = re.compile(r'''(?mx)
    ^\s*(?:from\s+([A-Za-z_][A-Za-z0-9_\.]*)\s+import|import\s+([A-Za-z_][A-Za-z0-9_\.]*))
    |^\s*import\s*(?:\(\s*)?["']([^"']+)["']
''')
_QUOTED_PATH_RE = re.compile(r'["\']([A-Za-z0-9_.\-/]{3,})["\']')
_CALLISH_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(')

def dependency_tokens_from_text(text: str, language: str) -> Set[str]:
    out:Set[str]=set()
    for m in _IMPORT_RE.finditer(text):
        for g in m.groups():
            if g:
                out.update(tokens(g))
    for q in _QUOTED_PATH_RE.findall(text):
        if "/" in q or "." in q:
            out.update(tokens(q))
    for name in _CALLISH_RE.findall(text):
        out.add(name.lower())
    generic_stop={"return","if","for","while","switch","func","def","print","len","append","make","new"}
    return {x for x in out if len(x)>=3 and x not in generic_stop}

def expansion_features(path: str, dependency_tokens: Set[str], already_selected: Set[str]) -> Dict[str,int]:
    if path in already_selected or not eligible_path(path):
        return {"dependency_overlap":0,"basename_hit":0}
    pt=set(tokens(path))
    overlap=len(pt & dependency_tokens)
    stem=PurePosixPath(path.lower()).stem
    basename_hit=int(stem in dependency_tokens)
    return {"dependency_overlap":overlap,"basename_hit":basename_hit}

def expansion_select(
    tree_paths: Sequence[str],
    dependency_tokens: Set[str],
    already_selected: Sequence[str],
    round_number: int,
    remaining_budget: int,
) -> List[Dict[str,Any]]:
    if round_number not in {1,2}:
        raise ValueError("round_number must be 1 or 2")
    selected=set(already_selected)
    rows=[]
    for path in tree_paths:
        f=expansion_features(path, dependency_tokens, selected)
        if not (f["dependency_overlap"] or f["basename_hit"]):
            continue
        rows.append({"path":path,"features":f})
    rows.sort(key=lambda r:(-r["features"]["basename_hit"],-r["features"]["dependency_overlap"],r["path"]))
    limit=max(0,min(remaining_budget, MAX_TOTAL_FILES-len(selected)))
    return [{"round":round_number,"rank":i+1,**r} for i,r in enumerate(rows[:limit])]

def acquisition_plan_digest(rounds: Sequence[Sequence[Dict[str,Any]]]) -> str:
    basis=[[r["path"] for r in rows] for rows in rounds]
    return sha256_bytes(canonical_bytes(basis))
