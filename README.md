# Evidence-Aware Baseband CVE Reproducibility Artifact

This Git repository is a self-contained copy of the schema-2.9 analysis pipeline,
its source datasets, and the generated research datasets. Run all commands from
this directory. The locked Nix flake is the canonical execution environment.

## Current result

The input union contains 622 unique CVEs. The policy retains 590 records: 315
with explicit public memory-safety evidence and 275 under the declared
missing-evidence memory-bug assumption. It excludes 32 explicitly non-memory
weaknesses. The
retained impact classes are:

- 11 RCEs with public control-flow or execution evidence;
- 194 write-primitive records; and
- 385 conservative denial-of-service records, including 294 whose precise
  memory primitive is not public.

`Write Primitive` is intentionally broad: it requires an attacker-influenced
write-capable memory effect, but not arbitrary address or byte control. A
deterministic one-byte or null-byte overwrite remains in this class even when the
immediate demonstrated result is an assertion or baseband crash.

Bare `memory corruption` wording does not identify a primitive. Such records are
therefore included in the `Assumed memory bug` family with conservative DoS
impact unless independent public evidence confirms execution. The
`memory_safety_basis` field still distinguishes generic but explicit memory-
corruption wording from cases with no public memory-safety root cause at all.

The five derived bug families contain 295 assumed/unknown-primitive, 181
bounds-write/overflow, 63 bounds-read, 28 null-dereference, and 23
lifetime/pointer-misuse records.

## Directory layout

```text
baseband_cve_artifact/
├── README.md
├── flake.nix / flake.lock    # locked Python and Matplotlib environment
├── requirements.txt
├── fetch_json.py             # multi-source vendor/baseband CVE acquisition
├── test_fetch_json.py        # acquisition and regression tests
├── enrich.py                 # dataset generator and plotting pipeline
├── verify_outputs.py         # independent integrity/result checks
├── cve_table.typ             # manually curated enrichment input
├── saved_json/               # four copied vendor input collections
│   ├── cve_mediatek_clean.json
│   ├── cve_qualcomm_clean.json
│   ├── cve_samsung_clean.json
│   └── cve_unisoc_clean.json
├── fetched_json/             # review set from the latest high-recall scan
│   └── discovery_audit.json  # per-record signals and source provenance
└── outputs/                  # generated datasets, audit, manifest, and plots
```

## Reproduce with Nix

Enable flakes if they are not already enabled, then generate into a fresh
directory and verify the result:

```bash
nix --extra-experimental-features 'nix-command flakes' develop
python enrich.py --output regenerated
python verify_outputs.py regenerated
```

The same operations are exposed as flake apps, so entering a shell is optional:

```bash
nix --extra-experimental-features 'nix-command flakes' run .#enrich -- --output regenerated
nix --extra-experimental-features 'nix-command flakes' run .#verify -- regenerated
nix --extra-experimental-features 'nix-command flakes' flake check
```

The verification command ends with `Artifact verification: PASS`. The flake
check also runs the acquisition regression tests. The official `cvelistV5.git`
repository is a required, revision-locked flake input. `nix develop` exposes its
immutable checkout as `$CVELISTV5_DIR`, and the fetch app uses it automatically:

```bash
nix --extra-experimental-features 'nix-command flakes' run .#fetch -- \
  --output-dir fetched_json
```

Pass `--cve-list-dir` or `--cve-list-zip` only when intentionally overriding
the locked input. Dataset enrichment remains offline; acquisition can still
access Android and vendor sites unless their corresponding `--no-*` switches
are supplied.

## Python fallback

- Python 3.10 or newer
- `matplotlib` only for PNG figure generation

The checked-in outputs were generated with Python 3.10 and Matplotlib 3.10.9.
Dataset generation itself otherwise uses the Python standard library. The
pipeline makes no network requests at runtime. It generates one
identifier-specific NVD URL per CVE and encodes manually reviewed technical
sources and strict RCE decisions in `enrich.py`. URLs inherited from the source
JSON are stored separately as unverified candidates and never justify a
classification or evidence level.

Without Nix, create a virtual environment from this repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Generate into a fresh directory, leaving the checked-in outputs untouched:

```bash
python enrich.py --output regenerated
python verify_outputs.py regenerated
```

To regenerate the checked-in `outputs/` directory directly:

```bash
python enrich.py --output outputs
python verify_outputs.py outputs
```

For JSON and CSV generation without Matplotlib or figures:

```bash
python enrich.py --output regenerated --no-plots
python verify_outputs.py regenerated --allow-no-plots
```

## Generator inputs

`enrich.py` reads the four files under `fetched_json/` and `cve_table.typ`. It
normalizes and unions them by CVE identifier, applies the documented
memory-safety filter, and generates the evidence-aware taxonomy.

The important classification axes are deliberately independent:

- `impact`: RCE, Write Primitive, or DoS;
- `bug_class`: the most specific public memory operation;
- `bug_family`: a five-family comparison layer in which unknown primitives are
  grouped as assumed memory bugs;
- `memory_safety_basis`: explicit public evidence or the missing-evidence
  assumption;
- `primary_scope`: cellular control plane, IMS/telephony, SIM/UICC, IP/user
  plane, local/IPC and diagnostic, or Unknown;
- `rats` and `protocols`: multi-valued radio-generation and protocol fields;
- `reachability`: the public attacker-path statement; and
- `evidence`: E1 (vendor/CVE statement), E2 (reproduction or detailed root
  cause), E3 (attacker-relevant memory primitive), E4 (control-flow
  redirection), or E5 (arbitrary code execution demonstrated or explicitly
  confirmed), plus independent evidence flags;

Source provenance is represented explicitly:

- `sources` contains only the generated CVE-specific NVD record plus any
  manually content-reviewed advisory or technical source;
- each source states its role, CVE association, verification method, and check
  date where applicable.

Specific read/crash CWEs take precedence over generic phrases such as “memory
corruption” or “could lead to RCE.” RCE requires public control-flow or code-
execution evidence rather than a CVSS score or maximum-impact statement.
CVE-2022-21744 is E5/RCE based on TASZK's full-chain exploitation write-up,
with the original PNCD post retained as its root-cause source. If no
public memory root cause exists and the record is not explicitly non-memory, it
is retained as
`assumed-memory-bug` with conservative DoS impact.

## Generated datasets

- `baseband_memory_cves.json`: complete nested 590-record dataset
- `baseband_memory_cves.csv`: flat analysis-friendly export of the same CVEs
- `excluded_non_memory_cves.json`: 32 explicit non-memory exclusions
- `rce_candidate_audit.json`: decisions and sources for all 46 legacy RCE
  candidates
- `source_provenance_audit.json`: source policy, reviewed source associations,
  inherited-candidate counts, and obvious cross-CVE URL conflicts
- `classification_summary.json`: aggregate counts, per-scope profiles,
  evidence coverage, and research-question results
- `dataset_manifest.json`: schema release, source-audit date, input hashes,
  exact `enrich.py` hash, and validation assertions

## Discover additional vendor baseband CVEs

`fetch_json.py` no longer depends on an OpenCVE HTML search. It combines:

- a checkout or baseline ZIP of the official CVE List V5 corpus;
- Android Security Bulletin vendor/component tables;
- official Qualcomm, Samsung Semiconductor, MediaTek, and Unisoc security pages;
- the existing curated JSON, whose `typst_enrichment` fields are preserved; and
- a small regression list for confirmed bulletin/CNA metadata gaps, including
  CVE-2022-20210 as `Unisoc / Modem` based on the June 2022 Android bulletin,
  four MediaTek Nucleus NET modem records, and Qualcomm CVE-2018-13900.

The CVE List V5 repository is the CVE Program's supported bulk-download source:
<https://github.com/CVEProject/cvelistV5>. Clone it once and update it before a
new dataset release:

```bash
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git .cache/cvelistV5
# Later: git -C .cache/cvelistV5 pull --ff-only
```

Run the high-recall discovery into a review directory first. Android and official
vendor-site crawling are enabled by default:

```bash
python fetch_json.py \
  --cve-list-dir .cache/cvelistV5 \
  --since-year 2010 \
  --output-dir fetched_json
python -m unittest -v test_fetch_json.py
```

The resulting `discovery_audit.json` records, for every included CVE, the vendor
signals, baseband signals, discovery methods, contextual bulletin rows, source
URLs, whether it is new to the existing collection, and any CVE IDs whose
canonical record could not be fetched. The four `cve_*_clean.json` outputs retain
canonical CVE JSON 5 records and are compatible with `enrich.py`.

Useful narrower runs include:

```bash
# Reproduce the Unisoc regression and crawl its 2022 Android bulletin context.
python fetch_json.py --vendor Unisoc --since-year 2022 --until-year 2022 \
  --no-vendor-sites --output-dir fetched_unisoc

# Deterministically test merging/classification without network access.
python fetch_json.py --offline --cve-list-dir .cache/cvelistV5 \
  --output-dir fetched_offline
```

After reviewing `discovery_audit.json`, regenerate the checked-in acquisition
inputs explicitly:

```bash
python fetch_json.py --cve-list-dir .cache/cvelistV5 --output-dir saved_json
python enrich.py --output outputs
```

The acquisition step is intentionally high-recall: it collects baseband CVEs,
including non-memory weaknesses. The later `enrich.py` stage applies the declared
memory-safety filter. Adding CVEs changes frozen research counts, so update and
review the numerical assertions in `verify_outputs.py` rather than weakening them.

## Generated figures

- `memory_cves_by_year_impact.png`
- `memory_cves_impact_by_scope.png`
- `memory_bug_classes.png`
- `memory_bug_families_by_scope.png`
- `public_evidence_coverage.png`

All counts describe public disclosure records in this corpus. They are not
normalized vulnerability rates and must not be interpreted as vendor-security
rankings.

## Integrity and expected determinism

`dataset_manifest.json` records SHA-256 hashes for every input and the generator
implementation. `verify_outputs.py` independently checks those hashes, unique
CVE identifiers, disjoint inclusion/exclusion sets, JSON/CSV agreement, the
expected impact/scope/bug-family totals, the 46-record RCE audit, CVE-specific
canonical sourcing, quarantine of inherited URLs, retained-RCE research
sourcing, and plot presence.

JSON and CSV content is deterministic for a fixed Python implementation and
fixed inputs. PNG byte hashes can vary between Matplotlib versions even when
the plotted values are identical, which is why the verifier checks their
presence while validating the underlying values from JSON.
