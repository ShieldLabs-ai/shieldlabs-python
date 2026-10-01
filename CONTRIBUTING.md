# Contributing

Thank you for helping improve the ShieldLabs Python SDK.

## Set up

Check out the repository, then:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Before you open a pull request

Run the same checks as CI:

```bash
ruff check . && ruff format --check . && mypy --strict src
pytest -q --cov=shieldlabs --cov-report=term-missing
```

- Every change comes with tests. Line coverage stays at 90% or above (CI enforces it).
- Code must run on Python 3.9: use `typing.Optional` and `typing.Union` in annotations.
- Keep httpx the only runtime dependency.
- Changes to the public API need an entry under `Unreleased` in `CHANGELOG.md`.
- The development tools have upper version bounds in `pyproject.toml`, so a new tool release
  cannot change CI results on its own. Raise a bound in its own pull request.
- The FastAPI example has its own smoke test:
  `pip install -r examples/requirements.txt && pytest tests/test_example_app.py`.

## Shared test fixtures

`tests/data/` holds the test fixtures that every ShieldLabs server SDK passes: History API
bodies, webhook bodies, signature vectors, error responses and the expected normalized results.
They are identical in every SDK and compared byte for byte (the `.raw.txt` files are exact
webhook bodies without a trailing newline), so do not edit them in a pull request. If a fixture
looks wrong, open an issue.

They come from `contract/` in shieldlabs-openapi. `contract-sync.json` maps each file,
`.shieldlabs-contract.lock` records the release they come from, and CI runs
`python3 scripts/sync_contract.py --check`. The `contract-sync.yml` workflow checks for a new
release every day and opens a pull request, with the test result, when it changes the files.

## Writing style

Docs, docstrings and comments use plain technical English and the terms used in the README.

## Commits

Use conventional commit messages: `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`.

## Releasing

Maintainers bump `src/shieldlabs/_version.py`, move the `Unreleased` notes under a new version
heading in `CHANGELOG.md`, and push a `vX.Y.Z` tag. The release workflow checks that the tag
matches the version, runs the checks, builds the package once and publishes that build to PyPI
with trusted publishing and attestations, from a separate job that runs in the `pypi`
environment.

One-time setup: on PyPI, add this repository, the workflow file `release.yml` and the
environment `pypi` as a trusted publisher of the `shieldlabs` project; on GitHub, protect the
`pypi` environment with required reviewers. No API token is stored in the repository.
Re-running the workflow for a tag is safe: files that are already on PyPI are skipped.

## Security

Please report vulnerabilities privately to contact@shieldlabs.ai instead of opening an issue.
