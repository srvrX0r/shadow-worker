# CI/CD Guide

How Shadow Worker is built, scanned, and released, and what the repository
ruleset requires before a pull request can merge into `main`.

## Workflows

| Workflow | File | Trigger | What it does |
|----------|------|---------|--------------|
| CI | `.github/workflows/ci.yml` | push to `main`, every pull request, manual | lint + tests on Python 3.10–3.14, wheel build and `shadow --help` smoke, dependency review, container build and runtime smoke test |
| CodeQL | `.github/workflows/codeql.yml` | push to `main`, every pull request, weekly, manual | CodeQL analysis of `src/`, SARIF upload to code scanning |
| Release | `.github/workflows/release.yml` | tag `v*` | sdist/wheel build, image push to `ghcr.io/srvrx0r/shadow-worker`, GitHub Release |

All workflows use least-privilege `permissions` blocks and a `concurrency`
group, so a superseded run is cancelled instead of queueing behind itself.

## Jobs in detail

### `test / py<version>`

Matrix: `3.10`, `3.11`, `3.12`, `3.13`, `3.14`.

- 3.10 is the floor declared in `pyproject.toml` (`requires-python = ">=3.10"`).
- 3.14 is the version baked into the container image, so it must stay in the
  matrix; the image and the test suite cannot drift apart silently.

The wheel build runs only on the highest version. It installs the built wheel
back into the environment and executes `shadow --help` / `shadow --version`,
which catches packaging regressions (missing package data, broken entry points)
that an editable install hides.

### `dependency review`

Runs on pull requests only, with `actions/dependency-review-action`. It fails a
pull request that introduces a dependency with a known vulnerability of `high`
or above. This does not need any token beyond `GITHUB_TOKEN`.

### `docker`

1. Builds the image with BuildKit and `load: true`, so the image is available to
   the following steps (a plain cache-only build cannot be executed).
2. Smoke tests the image:
   - `--version`, `--help`, `status` run inside the container
   - `os.getuid() == 10001` (non-root runtime, see `USER 10001:10001`)
   - `rules/**/*.yar` is present and `SHADOW_DATA_DIR` is writable
   - the `HEALTHCHECK` is declared

`make docker-test` runs the same assertions locally.

### `analyze / python` (CodeQL)

CodeQL uses the standard `github/codeql-action` advanced setup with
`.github/codeql/codeql-config.yml`.

The configuration deliberately keeps the **default** CodeQL security suite:

- The `Rules1` ruleset contains a `code_scanning` rule with
  `security_alerts_threshold: all`, so a single open CodeQL alert blocks every
  merge into `main`.
- Escalating to `security-extended` or `security-and-quality` is a follow-up
  once `main` has a clean baseline; doing it first would freeze merges.
- Third-party SARIF uploads (Trivy, Bandit, …) are intentionally not wired in
  for the same reason. If they are added later, relax the ruleset threshold
  first, or the alerts will block merges permanently.

`paths` is limited to `src/` because that is the shipped code. Tests are
excluded from analysis so test fixtures do not generate security alerts.


## Merge protection

The repository ruleset `Rules1` applies to `~ALL` refs and currently contains:

| Rule | Effect |
|------|--------|
| `deletion` | `main` cannot be deleted |
| `non_fast_forward` | no force pushes |
| `required_linear_history` | no merge commits; squash or rebase |
| `code_scanning` | CodeQL must have run, with no open alerts |
| `code_quality` | GitHub Code Quality findings are checked |
| `required_signatures` | pushed commits must have verified signatures |
| `copilot_code_review` | Copilot must review the pull request |
| `update` | the branch must be up to date before merging |

Some of these cannot be satisfied on this repository as configured, which is why
pull requests sit in `BLOCKED` even when every check is green:

- `code_quality` requires **GitHub Code Quality**, a separately licensed
  feature. Until it is enabled for the repository, the rule has no result to
  evaluate.
- `copilot_code_review` requires a **Copilot** seat.
- `required_signatures` blocks pushes made by automation. A GitHub App
  installation token pushing over `git` produces unsigned commits, and the push
  is rejected with `Commits must have verified signatures` — Dependabot commits
  are signed because GitHub creates them server-side, but CI or agent pushes are
  not.
- `required_linear_history` is evaluated against the pushed history. Because
  `main` already contains merge commits (`30a14eb`, `f36900f`, `59f37dd`),
  pushing a brand-new branch cut from `main` is rejected with
  `This branch must not contain merge commits` before a single new commit is
  reviewed.

Recommended remediation (repository admin required):

1. Scope the ruleset to the default branch: `conditions.ref_name.include =
   ["~DEFAULT_BRANCH"]`. Feature branches then stop being audited for merge
   commits and signatures; `main` keeps both protections.
2. Add the automation identity as a **bypass actor** for the
   `required_signatures` and `required_linear_history` rules instead of
   removing them.
3. Remove `code_quality` and `copilot_code_review`, or enable those products.
4. Keep `code_scanning`; `.github/workflows/codeql.yml` now produces the
   required results on every pull request.
5. Optionally require the CI checks explicitly.

```bash
# Inspect the current ruleset
gh api repos/srvrX0r/shadow-worker/rulesets
gh api repos/srvrX0r/shadow-worker/rulesets/<id> > ruleset.json

# Apply an edited ruleset (needs admin or "edit repository rules")
gh api -X PUT repos/srvrX0r/shadow-worker/rulesets/<id> --input ruleset.json
```

Direct `git push` to a protected branch is not the supported path. Merge with
squash through a pull request, so the commit on `main` is signed by GitHub.

## Release

Pushing a tag such as `v1.2.0` runs `release.yml`:

1. `package` builds the sdist and wheel on 3.14, verifies the wheel installs,
   and uploads the artifacts.
2. `container` logs into `ghcr.io`, derives semver tags plus a `sha-` tag from
   `docker/metadata-action`, and pushes the image with provenance.
3. `github` downloads the artifacts and publishes the GitHub Release.

The label `org.opencontainers.image.version` comes from the `VERSION` build
arg, so `docker build --build-arg VERSION=<x.y.z>` keeps labels in step with the
tag.

## Dependabot

`.github/dependabot.yml` groups updates to cut review noise:

- `pip` — one grouped pull request for minor/patch updates, majors separate
- `github-actions` — one grouped pull request
- `docker` — base image bumps

Dependabot pull requests still have to satisfy the ruleset described above.

## Local equivalents

```bash
make ci          # ruff + pytest, the gates from the test job
make docker-test # build the image and run the container smoke tests
make compose-up  # run the compose stack (read-only rootfs, non-root user)
```
