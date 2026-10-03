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
python scripts/generate_wire.py --check
python scripts/check_wire_drift.py
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

## Updating the HTTP contract

`resources/shieldlabs-api.yaml` is the bundled OpenAPI input. Run
`python scripts/generate_wire.py` after updating it. The deterministic output
`src/shieldlabs/_generated_wire.py` is included in the wheel and is read by the real
History/profile/webhook normalizers and request builders. PyYAML and the pinned formatter
are development dependencies only; the installed SDK still depends only on httpx.

The generated fields describe wire types, while the boundary helpers retain missing/null/
malformed-value defaults, unknown strings and raw fields. They do not validate entire
responses or coerce UUIDs/dates. The strict models under `generated/` require extra runtime
dependencies and reject values the supported client accepts, so they remain reference code.
`./generate.sh` regenerates both layers (Docker is needed only for the reference client).

The mutation check regenerates temporary schemas and type-checks copies of the actual SDK
source. Renamed fields, incompatible types, query parameters and headers must be rejected;
optional additive fields and parameters must compile. Unsupported new required parameters
on the consumed HTTP operations fail generation, including inherited path-level parameters.
The profile request path comes from the operation's OpenAPI route; a mutation test verifies
the changed route reaches an actual mocked HTTP request. Ping timestamp and version fields
are checked against the ping model separately from scored events. The checks never edit the
checked-in API description.

History's route template also comes from OpenAPI, with lookup values escaped before template
substitution. The current HTTP operations require GET; changing their method fails generation.
The generated lookup enum must match the real validation list before generation proceeds.
Public and local IP objects have separate generated fields, so one can change without hiding
an incompatible change in the other. Both webhook discriminator definitions are checked
against the supported envelope field and event values before generating.

To check the installed artifact without an editable checkout:

```bash
python -m pip install build
python -m build
python -m venv .wheel-consumer
.wheel-consumer/bin/pip install dist/*.whl
.wheel-consumer/bin/python scripts/smoke_wheel.py
```

## Shared test fixtures

`tests/data/` holds the test fixtures that every ShieldLabs server SDK passes: History API
bodies, webhook bodies, signature vectors, error responses and the expected normalized results.
They are identical in every SDK and compared byte for byte (the `.raw.txt` files are exact
webhook bodies without a trailing newline), so do not edit them in a pull request. If a fixture
looks wrong, open an issue.

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
