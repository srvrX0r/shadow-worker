# Pending workflow patch

`.github/workflows/` cannot be written by the automation identity that maintains
this repository: GitHub refuses App pushes that create or update workflow files
unless the App holds the **Workflows: Read and write** permission. Every other
change from the `1.2.0` CI/CD hardening is already on `main`.

Apply the pending pipeline changes with:

```bash
# from the repository root, on a clean checkout of main
git apply --index docs/patches/0001-ci-workflows.patch
git rm -r --cached docs/patches && rm -rf docs/patches
git commit -m "ci: add CodeQL scanning, extend matrix, dependency review, container smoke test"
git push origin HEAD:refs/heads/ci-cd-workflows
```

That commit:

- adds `.github/workflows/codeql.yml` and `.github/codeql/codeql-config.yml`
  (CodeQL on pull request, push to `main`, weekly, and manual dispatch), which is
  what the `code_scanning` rule in the `Rules1` ruleset waits for;
- extends the test matrix to 3.13/3.14 and builds the wheel on 3.14;
- adds a `dependency-review` job for pull requests;
- turns the container job into a real gate: build with `load: true`, then assert
  `--version`/`--help`/`status`, uid `10001`, baked YARA rules, a writable
  `SHADOW_DATA_DIR`, and the declared healthcheck;
- bumps `docker/login-action` v4, `docker/build-push-action` v7,
  `actions/upload-artifact` v7, `actions/download-artifact` v8, verifies the
  wheel installs before publishing, adds provenance, and scopes permissions per
  job.

The three files pass `actionlint` 1.7.12 with the `shellcheck` and `pyflakes`
rules enabled. Once this commit is on `main`, delete this directory and the
`handoff-ci-cd-hardening-1.2.0` tag.
