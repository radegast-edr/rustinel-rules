# rustinel-rules

> Official, curated detection content for the [Rustinel](https://github.com/Karib0u/rustinel) endpoint detection engine.

`rustinel-rules` is the **trusted, versioned, tested and reproducible** detection-content
repository for Rustinel. It ships ready-to-load **Sigma**, **YARA** and **IOC** packs that
plug straight into the engine — no glue, no conversion step.

```text
rustinel        →  the engine / agent / runtime
rustinel-rules  →  the detection content it loads   (this repo)
```

Each detection lives **once** in `rules/`, carries a stable `id`, and is referenced from
**packs** by that id. CI validates every change (Detection as Code) and builds flat, zipped
packs plus an `index.json` catalog that an installer can wire into Rustinel automatically.

---

## Quick start

```bash
# 0. Install the pinned tooling (uv: https://docs.astral.sh/uv/)
uv sync

# 1. Validate all rules and pack manifests (Detection as Code)
uv run python tools/validate.py

# 2. Build engine-ready packs into dist/ (folders + zips + index.json)
uv run python tools/build_packs.py
```

Then point Rustinel at a built pack — a materialized pack folder **is** the directory Rustinel
loads:

```toml
# config.toml
[scanner]
sigma_rules_path = "windows-essential/rules/sigma"
yara_rules_path  = "windows-essential/rules/yara"

[ioc]
hashes_path      = "windows-essential/rules/ioc/hashes.txt"
ips_path         = "windows-essential/rules/ioc/ips.txt"
domains_path     = "windows-essential/rules/ioc/domains.txt"
paths_regex_path = "windows-essential/rules/ioc/paths_regex.txt"
```

The exact paths for every pack are emitted under each pack's `engine` key in `dist/index.json`.
The default Essential packs ship the **EICAR** test IOC set — drop an EICAR test file on disk to
confirm detection is wired end to end. Full instructions: **[docs/usage.md](docs/usage.md)**.

---

## Packs

Packs are **cumulative** — a higher level `extends` the one below it, so rules are never
duplicated:

```text
Essential  ⊂  Advanced  ⊂  Hunting
```

| Pack                  | Level     | Default | Description                                                          |
| --------------------- | --------- | :-----: | -------------------------------------------------------------------- |
| **Windows Essential** | essential |   ✅    | Low-noise, high-confidence Windows detections. Safe default.        |
| **Windows Advanced**  | advanced  |   ❌    | Essential + broader production detections. More FPs may occur.       |
| **Windows Hunting**   | hunting   |   ❌    | Advanced + broad/noisier hunting content for analysts.              |
| **Linux Essential**   | essential |   ✅    | Low-noise, high-confidence Linux detections. Safe default.          |
| **Linux Advanced**    | advanced  |   ❌    | Essential + broader Linux detections (persistence, exec).           |

See the full catalog and per-pack rule inventory in **[docs/packs.md](docs/packs.md)**.

---

## Repository structure

```text
rustinel-rules/
├── rules/                  # Canonical source tree (each artifact exists ONCE)
│   ├── sigma/<os>/         # Sigma rules (.yml)
│   ├── yara/<os>/          # YARA rules (.yar)
│   └── ioc/<os|common>/    # IOC sets (.yml — typed: hashes / ips / domains / paths_regex)
├── packs/                  # Pack manifests (reference artifacts by id; never copies)
│   ├── windows/{essential,advanced,hunting}/pack.yml
│   └── linux/{essential,advanced}/pack.yml
├── schemas/                # JSON Schema for pack.yml and IOC sets (v1)
├── tools/                  # Build + validation tooling (lib.py, validate.py, build_packs.py)
├── docs/                   # Documentation (you are here)
├── dist/                   # Build output (gitignored): packs + zips + index.json
└── .github/workflows/      # CI: validate + build
```

---

## Documentation

| Doc | What's inside |
| --- | ------------- |
| **[docs/index.md](docs/index.md)** | Documentation map / start here |
| **[docs/repository.md](docs/repository.md)** | How the repo works: artifact model, packs, the build pipeline |
| **[docs/packs.md](docs/packs.md)** | Pack catalog and the full rule inventory |
| **[docs/rustinel-support.md](docs/rustinel-support.md)** | **What Rustinel supports**: telemetry, fields, Sigma operators, YARA, IOC |
| **[docs/usage.md](docs/usage.md)** | Installing packs and the Rustinel `config.toml` reference |
| **[docs/authoring.md](docs/authoring.md)** | Writing rules that load and fire on Rustinel |
| **[docs/detection-as-code.md](docs/detection-as-code.md)** | CI checks and the dynamic-testing policy |

---

## Versioning & compatibility

`rustinel-rules` is versioned **independently** from Rustinel — detection content evolves faster
than the engine. Compatibility is explicit in each pack manifest:

```yaml
pack_schema_version: 1
requires_rustinel: ">=1.0.2"
```

Release artifacts include zip packs, `index.json`, compatibility metadata, and a
`sha256` per artifact (already emitted in `index.json`).

---

## Guiding principles

- Start small — a few proven detections beat many noisy ones
- Avoid noisy defaults; keep Essential strict and low-FP
- No duplicated rules — each lives once, packs reference by id
- Keep Rustinel usable out of the box
- Make quality visible through CI
- Prefer TTP / telemetry-based curation; use CTI to **prioritize**, not to bulk-import

---

## Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)** and **[docs/authoring.md](docs/authoring.md)**. New
detections should be TTP/Atomic-based, mapped to ATT&CK, and compatible with Rustinel telemetry.

## License

See [LICENSE](LICENSE).
</content>
</invoke>