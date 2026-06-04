# Repository model

How `rustinel-rules` is organized, how packs reference detections, and how the build turns the
source tree into something Rustinel loads.

## The two-repo split

| Repo | Role |
| ---- | ---- |
| [`rustinel`](https://github.com/Karib0u/rustinel) | The engine: collects telemetry, evaluates rules, writes alerts. |
| `rustinel-rules` | The detection **content** the engine loads (this repo). |

They are versioned independently — content evolves faster than the engine — and compatibility is
declared explicitly per pack (`requires_rustinel`). The repository **must remain usable by Rustinel
users out of the box**.

## Artifacts: each detection lives once

There are three detection kinds, and they share one model. Each is an **artifact** with a stable
`id`, stored once under `rules/`, and referenced from packs by that id.

| Kind | Location | `id` source | Loaded by Rustinel as |
| ---- | -------- | ----------- | --------------------- |
| **Sigma** | `rules/sigma/<os>/*.yml` | `id:` (UUID v4) | `scanner.sigma_rules_path` |
| **YARA** | `rules/yara/<os>/*.yar` | `meta: id = "..."` (else rule name) | `scanner.yara_rules_path` |
| **IOC set** | `rules/ioc/<os\|common>/*.yml` | `id:` (prefixed `ioc-`) | flattened into `[ioc]` files |

> **Rules are never manually duplicated across packs.** A rule appears in exactly one file; packs
> include it by listing its id. This is enforced by the unique-id check in `validate.py`.

An **IOC set** is a typed collection — a campaign or tool yields many indicators (hashes, IPs,
domains, path regexes) grouped into one set. The build flattens every referenced set into the
per-type flat files the engine consumes.

## Packs: cumulative manifests

A pack is a manifest at `packs/<os>/<level>/pack.yml`. It lists the artifact ids it adds **on top
of** any pack it `extends`. Packs are cumulative:

```text
Essential  ⊂  Advanced  ⊂  Hunting
```

So Advanced `extends: [windows-essential]` and only lists the *extra* rules — it never re-lists
Essential's rules. The build resolves the full transitive membership (lower levels first,
de-duplicated). See the [pack catalog](packs.md) for the live set, and the
[pack schema](../schemas/pack.schema.json) for every field.

Key manifest fields:

| Field | Meaning |
| ----- | ------- |
| `id` / `name` | Stable id (`^[a-z0-9]+(-[a-z0-9]+)*$`) and human name. |
| `os` | `windows` \| `linux` \| `macos`. |
| `level` | `essential` \| `advanced` \| `hunting`. |
| `default` | Whether this pack is enabled by default. |
| `extends` | Pack ids cumulatively included (rules merged, never duplicated). |
| `rules` | Artifact ids added by *this* pack. |
| `requires_rustinel` | Engine version constraint, e.g. `">=1.0.2"`. |
| `attack_coverage` | ATT&CK technique ids covered (drift-checked against members). |
| `telemetry_requirements` | Rustinel telemetry channels the pack needs. |
| `expected_false_positive_level` / `status` / `test_status` | Quality signals surfaced in `index.json`. |

## The build pipeline

`one folder = one pack = one zipped Rustinel rules folder.`

The source repo uses manifests + canonical storage; CI generates the final flat, zipped pack
artifacts the engine consumes, plus an `index.json` catalog.

```bash
uv run python tools/validate.py        # gate: structure, metadata, ids, telemetry, IOC sanity
uv run python tools/build_packs.py     # materialize dist/ (folders + zips + index.json)
```

Output lands in `dist/`:

```text
dist/
├── index.json                       # Catalog of all packs (+ engine paths, sha256, counts)
├── windows-essential/               # Materialized flat pack folder (engine drop-in)
│   ├── pack.yml                      # Cleaned manifest + build metadata (version, counts)
│   └── rules/
│       ├── sigma/                    # .yml  -> scanner.sigma_rules_path
│       ├── yara/                     # .yar  -> scanner.yara_rules_path
│       └── ioc/                      # hashes.txt / ips.txt / domains.txt / paths_regex.txt
├── windows-essential-<version>.zip   # Rustinel-compatible artifact
└── ...
```

What the build does for each pack:

1. **Resolves** the cumulative rule list (`extends` + `rules`, de-duplicated).
2. **Copies** each Sigma/YARA file into the flat `rules/sigma` and `rules/yara` folders.
3. **Flattens** every referenced IOC set into the four per-type files in `VALUE;COMMENT` format,
   prefixing each line with its source set id (`[ioc-…]`) so provenance survives into alerts.
4. **Writes** a cleaned `pack.yml` with build metadata and zips the folder.
5. **Records** a catalog entry in `index.json` with engine paths and a `sha256`.

### `index.json` shape

Each pack entry includes drop-in `engine` paths so an installer can wire `config.toml`
automatically:

```json
{
  "id": "windows-essential",
  "version": "0.1.0",
  "default": true,
  "rule_count": 14,
  "ioc_count": 3,
  "sha256": "…",
  "artifact": "windows-essential-0.1.0.zip",
  "engine": {
    "sigma_rules_path": "windows-essential/rules/sigma",
    "yara_rules_path": "windows-essential/rules/yara",
    "hashes_path": "windows-essential/rules/ioc/hashes.txt",
    "ips_path": "windows-essential/rules/ioc/ips.txt",
    "domains_path": "windows-essential/rules/ioc/domains.txt",
    "paths_regex_path": "windows-essential/rules/ioc/paths_regex.txt"
  }
}
```

## Where to go next

- [Pack catalog & rule inventory](packs.md)
- [What Rustinel supports](rustinel-support.md) — before authoring anything
- [Using a pack with Rustinel](usage.md)
</content>
