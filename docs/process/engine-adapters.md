# Writing an engine adapter

This is the guide for anyone who adds an external analysis engine to CodeKavach (the adapters of
E15, E19 and E20). It states the rules of [ADR-0002](../adr/0002-external-engines-as-subprocesses.md)
as they are implemented in `codekavach.analysis.engines`, what an adapter has to provide, and the
checklist a reviewer applies.

An engine is a separate program. CodeKavach starts it as a process, hands it a read-only copy of
the source and reads its output. An adapter does not import the engine, and no engine package is
listed as a dependency.

## The rules of ADR-0002 and where each is implemented

| Rule | What it means for an adapter | Implemented in |
|------|------------------------------|----------------|
| No import | Do not import the engine or add it to `[project.dependencies]`. An import contract fails the build for the common engine packages. | `.importlinter` contract `adr0002-no-engine-imports` |
| No shell | Return an argument vector in `EngineInvocation.argv`. Do not build a command line from a string. | `sandbox.py` (`shell=False`) |
| Timeout | You do not set one. It comes from `engines.options.<id>.timeout_seconds`, the manifest row, or `engines.timeout_seconds`, and is cut to the remaining scan budget. | `scheduler.py`, `sandbox.py` |
| Output limit | Output over `engines.sandbox.max_output_bytes` is cut and the run is marked truncated. | `sandbox.py`, `runner.py` |
| Captured exit status | List the exit codes that mean success in `EngineSpec.expect_exit_codes`. Any other code is an `engine_error`. | `runner.py` |
| Scrubbed environment | The engine sees `PATH`, a private `HOME` and `TMPDIR`, `LANG`, the manifest's telemetry variables and only the names the operator lists in `env_passthrough`. A `CODEKAVACH_*` name is not passed (`tests/unit/analysis/engines/test_sandbox.py`). | `sandbox.py` (`build_environment`) |
| No network | A container runs with `--network=none`. The subprocess sandbox isolates the network on Linux when `unshare --user --net` works, and otherwise records `engine_network_not_isolated`. | `sandbox.py` |
| Read-only view | The engine runs in a read-only copy of the source with the repository's own engine configuration hidden. Write results only to the output directory. | `worktree.py` |
| Telemetry off | Record the engine's documented opt-out in the manifest. If it has none, say so there and pass its explicit disable flag in your argument vector. | `manifest.py`, your adapter |
| Version recorded | `probe` returns the version. It is stored with every run and every candidate. | `base.py`, `scheduler.py` |
| SARIF in | Convert at the boundary; the pipeline reads `Candidate` objects. An engine that writes SARIF calls `ingest_engine_run` from `parse` (see below). | your `parse`, `sarif/ingest.py` |

## What an adapter provides

An adapter is an object with a `spec: EngineSpec` and five methods (`EngineAdapter` in `base.py`).

| Member | Purpose |
|--------|---------|
| `spec` | Static facts, see the table below. |
| `probe(settings)` | Is the engine installed, and which version? Run `<engine> --version` or look the executable up; do not scan. |
| `applies_to(languages, files)` | Does the engine have anything to do for this scan? |
| `build_invocation(root, files, settings)` | The process to run, or `None` when nothing applies. Use `ROOT_TOKEN` and `OUTPUT_TOKEN` instead of real paths. |
| `parse(run, root)` | Candidates from `run.output_path`. Raise on malformed output; the scheduler records an `engine_error` and caches nothing. |
| `install_hint()` | One line telling the user how to install the engine. No network access. |

`root` is the read-only view, not the client's tree. An argument vector such as
`("opengrep", "scan", "--sarif-output", OUTPUT_TOKEN + "/out.sarif", ROOT_TOKEN)` stays valid
whatever temporary directory a run uses, which also keeps the cache key stable.

### `EngineSpec` fields

| Field | Meaning |
|-------|---------|
| `id` | Lower-case, starts with a letter, at most 32 characters of `a-z`, `0-9`, `-`. It is the key in `engines.enabled`, `engines.disabled` and `engines.options`. |
| `name` | Human-readable name for reports. |
| `languages` | `Language` members the engine handles; `UNKNOWN` is not allowed. |
| `tier` | `no_build` or `build` (the project must build first). |
| `output_format` | `sarif`, `json`, `xml` or `text`. |
| `spdx_licence` | SPDX identifier of the engine. |
| `distribution` | `bundled`, `client_installed` or `evaluation_only`. |
| `hosted_allowed` | False for network-copyleft tools: they are refused in a hosted deployment. |
| `scans_proprietary_code` | False when the licence does not clearly allow scanning proprietary code: the engine then needs a licence attestation. |
| `default_enabled` | Whether an empty `engines.enabled` includes it. |
| `homepage` | Where to read about the engine. |
| `config_filenames` | Names or patterns of the engine's own configuration files; they are hidden from the engine. |
| `expect_exit_codes` | Exit codes that mean the run worked (some engines exit 1 when they find issues). |
| `code_flow_order` | `source_first` or `sink_first`; read by the SARIF conversion. |
| `default_kind` | The `CandidateKind` of the engine's results. |
| `weight` | Scheduling cost from 1 to 16; a JVM side-car uses a high weight. |

The manifest row, when there is one, takes precedence over the licence, hosting and weight facts
in the spec, so a correction is a data change.

## Adding a manifest row

Rows live in `src/codekavach/analysis/engines/data/manifest.toml`, one table `[engines.<id>]` per
engine. The file explains every key. A row needs `pinned_version`, `min_version`, `spdx_licence`,
`distribution`, `hosted_allowed`, `scans_proprietary_code` and `install`. Add `image` (pinned by
`@sha256:` digest) if the engine can run in a container, and the telemetry opt-out:

```toml
[engines.example]
pinned_version = "1.2.3"
min_version = "1.2.0"
spdx_licence = "MIT"
distribution = "client_installed"
hosted_allowed = true
scans_proprietary_code = true
install = "pipx install example-engine"
telemetry_env = { EXAMPLE_NO_TELEMETRY = "1" }
```

A row without a documented opt-out must say `no_documented_opt_out = true`, and the loader refuses a
row that lists neither. The licence verdict itself is a human decision recorded in
`docs/research/INSIGHTS.md`; do not guess it.

## Reading SARIF

For an engine that writes SARIF, `parse` is one line:

```python
from codekavach.analysis.engines.sarif.ingest import ingest_engine_run

def parse(self, run: EngineRun, root: Path) -> Sequence[Candidate]:
    return ingest_engine_run(self.spec, run, root)
```

`ingest_engine_run` takes the code-flow order and the candidate kind from your `EngineSpec`, the
engine version from the probe, and returns candidates with locations resolved against the read-only
view, CWE, severity, confidence, a `ckfp1` fingerprint computed from the real file lines, and a
taint path where the code flow validates. It raises `SarifFormatError` for a log that is not
usable and `SarifSizeError` for one over the size limit; the scheduler turns either into an
`engine_error`.

What an adapter adds is data, not code:

| Table | Holds | Used for |
|-------|-------|----------|
| `data/cwe_fallback.toml` | rule id or rule-id prefix to CWE numbers, per engine id | engines that put no CWE in their SARIF |
| `data/severity_map.toml` | the engine's level map, confidence words and per-rule severities | engines whose vocabulary is not SARIF's `level` |

The CWE is looked up in the rule properties, then the rule tags, then the SARIF taxonomies, then
the fallback table, and `properties["cwe.source"]` records which one fired. A rule that names only
a Pillar-level weakness gets an empty `cwe` and `properties["cwe.unmapped"]`. Engine severity is an
opinion; the verdict is decided later.

Things the reader does on purpose: it ignores `region.snippet`, drops results whose file is not in
the view or whose URI leaves the root (counted in one `sarif_results_skipped` log event), keeps
engine partial fingerprints only as `sarif.partial_fingerprint.*` properties, carries suppressions
in `sarif.suppressed` without acting on them, and gives a secret candidate the rule's description
as its message instead of the engine's text.

## Recording a conformance case

A conformance case is a small, synthetic project plus the engine's real output saved as a file, in
`tests/fixtures/engines/<engine-id>/<case>/`:

| File | Content |
|------|---------|
| `spec.json` | `engine_version`, `output_file`, `languages`, and optionally `planted_secrets` (synthetic values that must not reach a candidate) |
| the output file | the engine's raw output, exactly as recorded |
| `expected_candidates.json` | the golden candidates, canonical JSON, with the random ids replaced by positions |
| `tree/` | the synthetic project the engine scanned |

`tests/integration/engines/test_conformance.py` runs `run_adapter_contract` over every case with no
engine installed. It checks the declared languages and tier, the argument vector (an executable
first, no shell metacharacter), the golden comparison, that every candidate validates and names only
files of the tree, and that no planted secret appears. Register your adapter in
`adapter_for` there, record a case with `uv run pytest --engines-live` (refused when `CI` is set;
it needs the engine installed), review the diff, and write the golden with
`CODEKAVACH_UPDATE_GOLDEN=1`. Use only synthetic code and the vendor-documented example values from
`AGENTS.md` section 3.

## Reviewer checklist

- [ ] The adapter imports no engine package and `argv` is a tuple of separate arguments.
- [ ] Paths are tokens, not temporary directories.
- [ ] `expect_exit_codes` lists every exit code that means success.
- [ ] The manifest row exists with a pinned version, a licence, and a telemetry opt-out or the
      explicit statement that there is none.
- [ ] `parse` raises on malformed output instead of returning an empty list.
- [ ] No engine output (stderr, snippets) goes into a log message or an error text.
- [ ] A secret candidate's `message` and `properties` hold no secret value.
- [ ] `config_filenames` lists the files the engine would otherwise read from the repository.
- [ ] There is a conformance case, and `probe` and `parse` are tested with the engine absent.
- [ ] The engine id is registered through the `codekavach.engines` entry-point group, and the
      distribution is one the operator allowed in `[plugins]`.

## Limits worth stating in a report

- The subprocess sandbox isolates the network only on Linux when user namespaces are available.
  On macOS and Windows an engine run that way can reach the network; the scan records
  `engine_network_not_isolated`.
- The read-only view uses file modes. It stops an engine that does not change modes itself; the
  container sandbox is the stronger control.
- A failing engine does not stop the scan. The failure is recorded as an item failure with one of
  `engine_unavailable`, `engine_timeout`, `engine_error`, `engine_output_truncated`,
  `engine_licence_blocked` or `engine_sandbox_error`, so the report can say which engine did not run.
