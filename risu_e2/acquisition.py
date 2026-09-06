from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any, Dict, List, Sequence, Set, Tuple

from .model import canonical_bytes, digest

SUPPORTED_CODE = {
    ".py": "python",
    ".go": "go",
    ".js": "typescript_javascript",
    ".jsx": "typescript_javascript",
    ".mjs": "typescript_javascript",
    ".cjs": "typescript_javascript",
    ".ts": "typescript_javascript",
    ".tsx": "typescript_javascript",
}
KNOWN_CODE = set(SUPPORTED_CODE) | {
    ".java", ".kt", ".kts", ".rs", ".rb", ".php", ".cs", ".swift",
    ".scala", ".c", ".cc", ".cpp", ".h", ".hpp",
}
DEFAULT_EXCLUDE_DIRS = {".git", "node_modules", "vendor", "third_party", "__pycache__", ".venv", "venv"}

PY_IMPORT = re.compile(r"(?m)^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*))")
GO_IMPORT = re.compile(r'(?m)(?:^\s*import\s+(?:[A-Za-z_][\w]*\s+)?"([^"]+)"|^\s*(?:[A-Za-z_][\w]*\s+)?"([^"]+)"\s*$)')
JS_IMPORT = re.compile(r'''(?mx)
    \b(?:import|export)\b[^;\n]*?\bfrom\s*["']([^"']+)["']
    |\bimport\s*["']([^"']+)["']
    |\brequire\s*\(\s*["']([^"']+)["']\s*\)
    |\bimport\s*\(\s*["']([^"']+)["']\s*\)
''')
CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
PY_DEF = re.compile(r"(?m)^\s*(?:async\s+)?def\s+([A-Za-z_][\w]*)\s*\(")
PY_CLASS = re.compile(r"(?m)^\s*class\s+([A-Za-z_][\w]*)\b")
GO_DEF = re.compile(r"(?m)^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)\s*\(")
GO_TYPE = re.compile(r"(?m)^\s*type\s+([A-Za-z_][\w]*)\b")
JS_DEF = re.compile(r"(?m)^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(")
JS_CLASS = re.compile(r"(?m)^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)\b")
JS_CONST_FN = re.compile(r"(?m)^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>")

@dataclass(frozen=True)
class AcquisitionConfig:
    max_files: int = 64
    max_rounds: int = 4
    max_file_bytes: int = 512_000
    max_total_bytes: int = 4_000_000
    max_index_files: int = 2048
    max_index_bytes: int = 16_000_000

    def as_dict(self) -> Dict[str, int]:
        return {
            "max_files": self.max_files,
            "max_rounds": self.max_rounds,
            "max_file_bytes": self.max_file_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_index_files": self.max_index_files,
            "max_index_bytes": self.max_index_bytes,
        }

@dataclass(frozen=True)
class AcquiredFile:
    path: str
    language: str
    sha256: str
    data: bytes
    selection_round: int
    selection_reasons: Tuple[str, ...]

    def record(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "language": self.language,
            "sha256": self.sha256,
            "bytes": len(self.data),
            "selection_round": self.selection_round,
            "selection_reasons": list(self.selection_reasons),
        }

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _norm(path: str) -> str:
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(f"unsafe path: {path}")
    return p.as_posix()

def detect_language(path: str) -> str | None:
    return SUPPORTED_CODE.get(PurePosixPath(path).suffix.lower())

def _inventory(root: Path) -> List[str]:
    out: List[str] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        parts = PurePosixPath(rel).parts
        if any(part in DEFAULT_EXCLUDE_DIRS for part in parts[:-1]):
            continue
        out.append(rel)
    return sorted(out)

def _read(root: Path, path: str, cfg: AcquisitionConfig) -> tuple[bytes | None, str | None]:
    p = root / path
    size = p.stat().st_size
    if size > cfg.max_file_bytes:
        return None, "FILE_BYTE_BUDGET_EXCEEDED"
    data = p.read_bytes()
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return None, "NON_UTF8_MATERIAL_FILE"
    return data, None

def _definitions(text: str, language: str) -> Set[str]:
    if language == "python":
        regs = (PY_DEF, PY_CLASS)
    elif language == "go":
        regs = (GO_DEF, GO_TYPE)
    else:
        regs = (JS_DEF, JS_CLASS, JS_CONST_FN)
    out: Set[str] = set()
    for reg in regs:
        out.update(m.group(1) for m in reg.finditer(text))
    return out

def _dependency_specifiers(text: str, language: str) -> Set[str]:
    out: Set[str] = set()
    if language == "python":
        for m in PY_IMPORT.finditer(text):
            out.update(x for x in m.groups() if x)
    elif language == "go":
        for m in GO_IMPORT.finditer(text):
            out.update(x for x in m.groups() if x)
    else:
        for m in JS_IMPORT.finditer(text):
            out.update(x for x in m.groups() if x)
    return out

def _call_names(text: str) -> Set[str]:
    stop = {"if", "for", "while", "switch", "return", "len", "print", "make", "new", "append"}
    return {x for x in CALL.findall(text) if x not in stop}

def _resolve_specifier(current: str, spec: str, inventory: Sequence[str], language: str) -> Set[str]:
    inv = set(inventory)
    curdir = PurePosixPath(current).parent
    cands: Set[str] = set()
    raw = spec.replace("\\", "/")
    if raw.startswith("."):
        base = (curdir / raw).as_posix()
        probes = [base, base + ".py", base + ".go", base + ".js", base + ".mjs", base + ".cjs", base + ".ts", base + ".tsx",
                  base + "/__init__.py", base + "/index.js", base + "/index.ts", base + "/index.mjs"]
        cands.update(p for p in probes if p in inv)
    elif language == "python":
        # Bare Python imports may resolve to a local module/package; JS bare imports and
        # Go module paths are not guessed from basenames because that can capture external packages.
        tail = raw.split(".")[-1]
        for p in inventory:
            stem = PurePosixPath(p).stem
            if stem == tail:
                cands.add(p)
    return cands

def _initial_rank(path: str, operation: str, surface_arguments: Sequence[str]) -> tuple[int, int, int, str]:
    low = path.lower()
    toks = set(re.findall(r"[a-z0-9]+", low))
    op = set(re.findall(r"[a-z0-9]+", operation.lower()))
    args = [re.sub(r"[^a-z0-9]+", "", x.lower()) for x in surface_arguments]
    overlap = len(toks & op)
    arg_hits = sum(1 for a in args if a and a in re.sub(r"[^a-z0-9]+", "", low))
    commandish = int(bool(toks & {"cmd", "command", "commands", "cli", "handler", "tool", "server"}))
    return (-arg_hits, -overlap, -commandish, path)

def acquire(
    root: Path,
    *,
    entrypoints: Sequence[str] = (),
    operation: str = "",
    surface_arguments: Sequence[str] = (),
    config: AcquisitionConfig = AcquisitionConfig(),
) -> tuple[Dict[str, Any], List[AcquiredFile]]:
    root = root.resolve()
    inventory = _inventory(root)
    invset = set(inventory)
    requested = [_norm(x) for x in entrypoints]
    missing = [p for p in requested if p not in invset]
    if missing:
        return ({
            "schema": "risu.e2-acquisition-result/v0.1",
            "status": "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION",
            "reason": "ENTRYPOINT_MISSING",
            "missing_entrypoints": missing,
            "config": config.as_dict(),
            "semantic_authority": False,
        }, [])
    unsupported_requested = [p for p in requested if PurePosixPath(p).suffix.lower() in KNOWN_CODE and detect_language(p) is None]
    if unsupported_requested:
        return ({
            "schema": "risu.e2-acquisition-result/v0.1",
            "status": "E2_PREDICTED_ASSURANCE_INCOMPLETE",
            "reason": "UNSUPPORTED_MATERIAL_LANGUAGE",
            "paths": unsupported_requested,
            "config": config.as_dict(),
            "semantic_authority": False,
        }, [])

    seeds = list(dict.fromkeys(requested))
    if not seeds:
        eligible = [p for p in inventory if detect_language(p)]
        eligible.sort(key=lambda p: _initial_rank(p, operation, surface_arguments))
        seeds = eligible[: min(4, config.max_files)]

    selected: Dict[str, AcquiredFile] = {}
    unresolved: List[Dict[str, Any]] = []
    total_bytes = 0

    def add(path: str, round_no: int, reasons: Sequence[str]) -> bool:
        nonlocal total_bytes
        if path in selected:
            return True
        lang = detect_language(path)
        if lang is None:
            if PurePosixPath(path).suffix.lower() in KNOWN_CODE:
                unresolved.append({"path": path, "reason": "UNSUPPORTED_MATERIAL_LANGUAGE"})
            return False
        data, err = _read(root, path, config)
        if err:
            unresolved.append({"path": path, "reason": err})
            return False
        assert data is not None
        if len(selected) >= config.max_files or total_bytes + len(data) > config.max_total_bytes:
            unresolved.append({"path": path, "reason": "ACQUISITION_BUDGET_EXHAUSTED"})
            return False
        selected[path] = AcquiredFile(path, lang, _sha(data), data, round_no, tuple(sorted(set(reasons))))
        total_bytes += len(data)
        return True

    for p in seeds:
        add(p, 0, ("EXPLICIT_ENTRYPOINT" if requested else "INITIAL_OPERATION_RANK",))

    definition_index: Dict[str, Set[str]] = {}
    indexed_files = 0
    indexed_bytes = 0
    index_exhausted = False
    for p in inventory:
        lang = detect_language(p)
        if not lang:
            continue
        q = root / p
        size = q.stat().st_size
        if size > config.max_file_bytes:
            continue
        if indexed_files >= config.max_index_files or indexed_bytes + size > config.max_index_bytes:
            index_exhausted = True
            break
        try:
            source_text = q.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        indexed_files += 1
        indexed_bytes += size
        for name in _definitions(source_text, lang):
            definition_index.setdefault(name, set()).add(p)
    if index_exhausted:
        unresolved.append({"path":"<inventory>","reason":"INDEX_BUDGET_EXHAUSTED",
                           "indexed_files":indexed_files,"indexed_bytes":indexed_bytes})

    for round_no in range(1, config.max_rounds + 1):
        proposals: Dict[str, Set[str]] = {}
        for p in sorted(selected):
            row = selected[p]
            text = row.data.decode("utf-8")
            for spec in sorted(_dependency_specifiers(text, row.language)):
                resolved = _resolve_specifier(p, spec, inventory, row.language)
                if not resolved and spec.startswith("."):
                    unresolved.append({"path": p, "reason": "UNRESOLVED_LOCAL_DEPENDENCY", "specifier": spec})
                for q in resolved:
                    if q != p:
                        proposals.setdefault(q, set()).add(f"IMPORT:{spec}")
            for name in sorted(_call_names(text)):
                defs = definition_index.get(name, set())
                if len(defs) == 1:
                    q = next(iter(defs))
                    if q != p:
                        proposals.setdefault(q, set()).add(f"UNIQUE_CALLEE_DEF:{name}")
        new = [(p, reasons) for p, reasons in proposals.items() if p not in selected]
        new.sort(key=lambda x: (sorted(x[1])[0], x[0]))
        if not new:
            break
        before = len(selected)
        for p, reasons in new:
            add(p, round_no, reasons)
        if len(selected) == before:
            break

    # De-duplicate unresolved diagnostics deterministically.
    uniq = {}
    for item in unresolved:
        uniq[canonical_bytes(item)] = item
    unresolved = [uniq[k] for k in sorted(uniq)]

    budget_faults = [x for x in unresolved if x["reason"] in {"ACQUISITION_BUDGET_EXHAUSTED", "FILE_BYTE_BUDGET_EXCEEDED", "INDEX_BUDGET_EXHAUSTED"}]
    material_faults = [x for x in unresolved if x["reason"] in {"UNSUPPORTED_MATERIAL_LANGUAGE", "NON_UTF8_MATERIAL_FILE"}]
    resolution_faults = [x for x in unresolved if x["reason"] == "UNRESOLVED_LOCAL_DEPENDENCY"]
    if material_faults:
        status, reason = "E2_PREDICTED_ASSURANCE_INCOMPLETE", "MATERIAL_ACQUISITION_UNSUPPORTED"
    elif budget_faults:
        status, reason = "E2_PREDICTED_ASSURANCE_INCOMPLETE", "ACQUISITION_BUDGET_EXHAUSTED"
    elif resolution_faults:
        status, reason = "E2_PREDICTED_ASSURANCE_INCOMPLETE", "UNRESOLVED_LOCAL_DEPENDENCY"
    else:
        status, reason = "PASS", "ACQUISITION_CLOSED_WITHIN_BUDGET"

    records = [selected[p].record() for p in sorted(selected)]
    doc = {
        "schema": "risu.e2-acquisition-result/v0.1",
        "status": status,
        "reason": reason,
        "semantic_authority": False,
        "config": config.as_dict(),
        "inventory_file_count": len(inventory),
        "indexed_file_count": indexed_files,
        "indexed_bytes": indexed_bytes,
        "selected_file_count": len(records),
        "selected_total_bytes": total_bytes,
        "selected_files": records,
        "unresolved": unresolved,
    }
    doc["acquisition_digest_sha256"] = digest(doc)
    return doc, [selected[p] for p in sorted(selected)]
