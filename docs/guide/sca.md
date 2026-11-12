# Dependency scanning (SCA) and SBOM

A scan reads the manifests and lock files of the project and reports components with known
vulnerabilities as findings with the weakness CWE-1395. Nothing about the dependency list leaves the
machine: advisories come to you, never the other way round.

## What is read

`requirements*.txt` (with `-r` and `-c` includes, hashes, markers, VCS and editable entries),
`pyproject.toml`, `poetry.lock`, `uv.lock`, `package.json`, `package-lock.json` (v1 to v3),
`yarn.lock` (classic and Berry), `pnpm-lock.yaml`, `pom.xml`, Gradle build files, `go.mod`,
`go.sum`, `Gemfile.lock`, `composer.lock` and `Cargo.lock`. A lock file wins over the manifest
beside it; the manifest then only marks components as direct and supplies the declared range.
Unpinned requirements are listed in the SBOM but not matched, because there is no version to match.

## Commands

```bash
codekavach sbom ./project                      # CycloneDX 1.5 on stdout
codekavach sbom ./project -f spdx -o sbom.json # SPDX 2.3 file
codekavach sca list ./project                  # vulnerable components against the local mirror
codekavach sca update                          # refresh the mirror (the one network action)
codekavach --offline sca update                # refused, before any connection
```

A scan also publishes the inventory (`dependencies`) and the CycloneDX document (`sbom`) as
artefacts and adds one candidate per vulnerable component.

## The advisory mirror

`codekavach sca update` downloads the public OSV snapshots, the CISA KEV catalogue and the FIRST
EPSS scores into `<user data dir>/codekavach/sca` (override with `CODEKAVACH_SCA_MIRROR`). The hosts
are fixed and listed in
[ADR-0003 exception](../adr/ADR-0003-exception-sca-mirror.md). Without a snapshot a scan uses the
small seed shipped with the package, which covers the packages planted in the sample project, and
the finding says that no KEV or EPSS data is installed.

## How a finding is built

- Version ranges follow each ecosystem's ordering (`analysis/sca/versions.py` documents the table).
- The remediation names the smallest version that resolves every listed advisory of the component.
- Reachability is a hint, not a filter: a package that is imported by the scanned code gets high
  confidence, one that is not imported gets low confidence and is still reported.
- Every exploitation number names its source and snapshot date.

## Not yet done

The OSV-Scanner and Trivy adapters, the NuGet and Gradle lock file parsers, licence extraction and
internal-package detection beyond name heuristics are follow-ups of E19. Dependency findings are
deterministic and are not sent to a model.
