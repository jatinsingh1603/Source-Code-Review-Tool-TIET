# Checkpoints and resuming a scan

A scan can be interrupted by Ctrl-C, a closed laptop, a CI time limit or a crash. `run_scan` keeps a checkpoint so that the scan can continue under the same scan id.

## The checkpoint

`<state_dir>/scans/<scan_id>/checkpoint.json` (mode `0o600`) is written before the first stage, after every stage that finishes, fails or is skipped, and when the scan ends. A killed process therefore leaves a checkpoint with status `running`.

| Field | Content |
|---|---|
| `v` | Format version, `1` |
| `scan_id` | The scan |
| `status` | `running`, `cancelled`, `failed`, `completed` or `completed_with_errors` |
| `codekavach_version` | Version that ran the scan |
| `settings_fingerprint` | Fingerprint of the result-affecting settings |
| `salt_fingerprint` | One-way fingerprint of the scan salt |
| `target_digest` | `sha256` of the target string |
| `order` | Stage names in plan order |
| `completed` | Recorded stage runs: `stage`, `outcome`, `stage_key`; cancelled stages are left out |
| `updated_at` | Time of the last write |

The checkpoint holds no salt, no target path, no client code and no vault material. The target is stored as a digest because a path can contain a user or client name.

## Resuming

`run_scan(..., resume="latest")` continues the newest scan whose checkpoint is `running`, `cancelled` or `failed`; `resume="<scan id>"` names one. The checks run in this order and the first failure raises `ResumeMismatchError` with the field name, before any stage runs:

1. `checkpoint`: a checkpoint exists
2. `status`: the scan is not `completed`
3. `codekavach_version`
4. `settings_fingerprint`
5. `salt_fingerprint`
6. `target_digest`

A resume under another salt or other settings is refused, because half of the payloads would carry different pseudonyms than the other half (I5). The messages name the field and do not print fingerprints.

A resumed scan keeps its scan id, its database row and the start time of its first attempt. It runs the plan again with the stage cache on:

- Outputs of stages that the checkpoint does not list as `succeeded` or `cached` are discarded first. A stage interrupted by a hard kill may have written part of its outputs; a resumed run does not consume them (I4).
- INGEST runs again, because the working tree may have changed. Changed digests make downstream stages recompute.
- Cacheable stages that completed before the interruption are cache hits.
- PRIVACY, LLM and RESTORE stages always run again. With the same salt and settings their payloads are byte-identical to the first attempt.

## Interrupting a scan

With `run_scan(..., handle_sigint=True)` the first SIGINT (Ctrl-C) or SIGTERM cancels the scan cooperatively: no new stage starts, the running stage stops at its next cancellation check and its outputs are discarded, and the manifest and the checkpoint are written with status `cancelled`. A second signal exits the process at once with status 130. The checkpoint then stays at `running`, which is resumable; a temporary file may remain inside the state directory. The previous signal handlers are restored when `run_scan` returns.

How fast the first signal takes effect depends on the running stage: a stage that checks for cancellation stops within one unit of work, and one that does not is abandoned when its timeout expires. SIGTERM is skipped on platforms where it cannot be registered.

## Known limit

Until the LLM response cache (E22) exists, a resumed scan can send payloads that the first attempt already sent. The payloads are identical, so nothing new leaves the machine, but the provider is called and billed again.
