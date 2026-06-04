"""Shared helpers for rustinel-rules tooling.

Loads the canonical detection sources — Sigma rules, YARA rules and IOC sets —
plus the pack manifests, and resolves the cumulative (`extends`) membership of
each pack.

Each detection artifact (Sigma rule, YARA rule, IOC set) lives **once** under
`rules/` and carries a stable `id`. Packs reference those ids and never copy
content. A pack materializes (see ``build_packs.py``) into exactly the layout the
Rustinel engine loads:

    rules/sigma/   recursive dir of Sigma .yml      -> scanner.sigma_rules_path
    rules/yara/    recursive dir of YARA .yar       -> scanner.yara_rules_path
    rules/ioc/hashes.txt  ips.txt  domains.txt  paths_regex.txt
                                                    -> [ioc].*_path

Requires PyYAML (see tools/requirements.txt).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
PACKS_DIR = REPO_ROOT / "packs"
SCHEMA_DIR = REPO_ROOT / "schemas"
PACK_SCHEMA_PATH = SCHEMA_DIR / "pack.schema.json"
IOC_SCHEMA_PATH = SCHEMA_DIR / "ioc.schema.json"
DIST_DIR = REPO_ROOT / "dist"

# Canonical source globs, one per artifact kind.
SIGMA_GLOB = "sigma/**/*.yml"
YARA_GLOB = "yara/**/*.yar"
IOC_GLOB = "ioc/**/*.yml"

# IOC indicator types, in the order they are emitted. These map 1:1 onto the
# flat files the Rustinel `[ioc]` config consumes.
IOC_TYPES: tuple[str, ...] = ("hashes", "ips", "domains", "paths_regex")


class Artifact:
    """A single canonical detection source: a Sigma rule, YARA rule or IOC set.

    `kind` is one of "sigma" | "yara" | "ioc". `meta` holds the parsed document
    (Sigma/IOC) or extracted fields (YARA); `raw` is the original file text.
    """

    def __init__(self, artifact_id: str, kind: str, path: Path, meta: dict, raw: str):
        self.id = artifact_id
        self.kind = kind
        self.path = path
        self.meta = meta
        self.raw = raw

    @property
    def rel_path(self) -> str:
        return str(self.path.relative_to(REPO_ROOT))

    @property
    def indicators(self) -> dict[str, list[tuple[str, str | None]]]:
        """Normalized IOC indicators (empty for non-IOC artifacts)."""
        return parse_ioc_indicators(self.meta) if self.kind == "ioc" else {t: [] for t in IOC_TYPES}


# --------------------------------------------------------------------------- #
# Loaders
# --------------------------------------------------------------------------- #


def load_sigma_rules() -> list[Artifact]:
    artifacts: list[Artifact] = []
    for path in sorted(RULES_DIR.glob(SIGMA_GLOB)):
        raw = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(raw) or {}
        rule_id = str(doc.get("id", "")).strip()
        artifacts.append(Artifact(rule_id, "sigma", path, doc, raw))
    return artifacts


_YARA_RULE_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)")
_YARA_META_ID_RE = re.compile(r'\bid\s*=\s*"([^"]+)"')
_YARA_META_ATTACK_RE = re.compile(r'\battack\s*=\s*"([^"]+)"')


def load_yara_rules() -> list[Artifact]:
    artifacts: list[Artifact] = []
    for path in sorted(RULES_DIR.glob(YARA_GLOB)):
        raw = path.read_text(encoding="utf-8")
        meta_id = _YARA_META_ID_RE.search(raw)
        name = _YARA_RULE_RE.search(raw)
        rule_id = (meta_id.group(1) if meta_id else name.group(1) if name else "").strip()
        meta = {"rule_name": name.group(1) if name else None}
        artifacts.append(Artifact(rule_id, "yara", path, meta, raw))
    return artifacts


def load_ioc_sets() -> list[Artifact]:
    artifacts: list[Artifact] = []
    for path in sorted(RULES_DIR.glob(IOC_GLOB)):
        raw = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(raw) or {}
        set_id = str(doc.get("id", "")).strip()
        artifacts.append(Artifact(set_id, "ioc", path, doc, raw))
    return artifacts


def load_all_artifacts() -> list[Artifact]:
    return load_sigma_rules() + load_yara_rules() + load_ioc_sets()


def artifacts_by_id() -> dict[str, Artifact]:
    index: dict[str, Artifact] = {}
    for artifact in load_all_artifacts():
        if artifact.id:
            index[artifact.id] = artifact
    return index


# --------------------------------------------------------------------------- #
# IOC + ATT&CK helpers (shared by validate.py and build_packs.py)
# --------------------------------------------------------------------------- #


def parse_ioc_indicators(doc: dict) -> dict[str, list[tuple[str, str | None]]]:
    """Normalize an IOC set's `indicators` block into {type: [(value, comment)]}.

    Each entry may be a bare scalar (the value) or a mapping {value, comment}.
    Unknown indicator types are ignored here and flagged by validation.
    """
    result: dict[str, list[tuple[str, str | None]]] = {t: [] for t in IOC_TYPES}
    for ioc_type, entries in (doc.get("indicators") or {}).items():
        if ioc_type not in IOC_TYPES:
            continue
        for entry in entries or []:
            if isinstance(entry, dict):
                value = str(entry.get("value", "")).strip()
                comment = entry.get("comment")
                comment = str(comment).strip() if comment else None
            else:
                value = str(entry).strip()
                comment = None
            if value:
                result[ioc_type].append((value, comment))
    return result


_SIGMA_TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def artifact_attack_techniques(artifact: Artifact) -> set:
    """Best-effort set of ATT&CK technique ids (e.g. {"T1059.001"}) declared by
    an artifact, used to detect pack attack_coverage drift."""
    techniques: set = set()
    if artifact.kind == "sigma":
        for tag in artifact.meta.get("tags") or []:
            match = _SIGMA_TECHNIQUE_RE.match(str(tag))
            if match:
                techniques.add(match.group(1).upper())
    elif artifact.kind == "yara":
        match = _YARA_META_ATTACK_RE.search(artifact.raw)
        if match:
            techniques.add(match.group(1).strip().upper())
    elif artifact.kind == "ioc":
        for technique in artifact.meta.get("attack") or []:
            techniques.add(str(technique).strip().upper())
    return techniques


# --------------------------------------------------------------------------- #
# Packs
# --------------------------------------------------------------------------- #


def load_packs() -> list[dict]:
    packs: list[dict] = []
    for path in sorted(PACKS_DIR.glob("**/pack.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        doc["__path__"] = path
        packs.append(doc)
    return packs


def packs_by_id() -> dict[str, dict]:
    return {p["id"]: p for p in load_packs() if "id" in p}


def resolve_pack_rules(pack: dict, by_id: dict[str, dict]) -> list[str]:
    """Return the ordered, de-duplicated artifact ids for a pack, including all
    transitively extended packs. Lower-level packs come first.

    Raises ValueError on a missing extends target or an extends cycle.
    """
    ordered: list[str] = []
    seen: set = set()

    def visit(pack_id: str, stack: list[str]):
        if pack_id in stack:
            raise ValueError(f"extends cycle: {' -> '.join(stack + [pack_id])}")
        if pack_id not in by_id:
            raise ValueError(f"unknown pack in extends: {pack_id}")
        node = by_id[pack_id]
        for parent in node.get("extends", []) or []:
            visit(parent, stack + [pack_id])
        for rule_id in node.get("rules", []) or []:
            if rule_id not in seen:
                seen.add(rule_id)
                ordered.append(rule_id)

    visit(pack["id"], [])
    return ordered
