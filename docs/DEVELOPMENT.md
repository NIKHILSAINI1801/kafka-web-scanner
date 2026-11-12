# Development guide

## Set up

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux:        source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The developer extras install `pytest`, `ruff`, `build` and `cryptography` (the integration
tests use it to create throw-away TLS certificates; those tests are skipped if it is missing).

> The package imports as `kafka`, which is also the name of the unrelated `kafka-python`
> library. Use a clean virtual environment and do not install both.

## Quality gates

Run these before every commit; CI runs the same commands:

```bash
python -m pytest -q
ruff check .
ruff format --check .      # use `ruff format .` to fix
python -m build
python -m pip install dist/*.whl   # preferably in a fresh virtual environment
kafka --help
kafka doctor
```

## Tests

* `tests/unit/`: pure unit tests (URL validation, address blocking, each module, reports,
  SQLite, CLI via `typer.testing.CliRunner`).
* `tests/integration/`: a local HTTP/HTTPS server (`tests/integration/conftest.py`) that
  records every request. They verify: exactly one GET, redirects not followed, timeouts,
  size cap, TLS verification, report creation and "declined means no request".
  **Tests never contact a real website.**
* `tests/fixtures/`: HTML pages and a `Set-Cookie` sample file with "canary" values that must
  never appear in output.

## Project conventions

* New findings need a stable ID, a unit test, and (if user-visible) a docs mention. Never
  reuse or renumber an ID.
* Anything that came from the server must go through `Finding`/`clean_text` and be rendered
  with `Text`/auto-escaping.
* Never add a second request, a redirect follow, a crawler, or anything that sends data other
  than the single GET.

## Adding a module

1. Create `kafka/modules/<name>.py` exposing `scan(snapshot: ResponseSnapshot) -> list[Finding]`.
   It must be pure (no network, no files).
2. Register it in `kafka/modules/__init__.py` (`MODULES`) with a unique `finding_prefix`.
   Extend the finding-ID regex in `kafka/models.py` only if the prefix needs more than four letters.
3. Add unit tests under `tests/unit/`, including hostile input.
4. Update the README module table and `docs/ARCHITECTURE.md`.

## Releasing

1. Update `__version__` in `kafka/__init__.py`, `CHANGELOG.md` and `RELEASE_NOTES.md`.
2. Run all quality gates locally and confirm CI is green on `main`.
3. Review the tree for secrets, personal data, local databases and generated reports.
4. Tag and push: `git tag v1.0.0 && git push origin v1.0.0`.
5. Optionally create a GitHub Release and attach the files from the CI `dist` artifact.
6. Test installation from the built wheel on a different machine / clean environment.

### First-time repository setup (owner steps)

```bash
git init
git add .
git commit -m "Initial KAFKA v1.0.0 release"
git branch -M main
git remote add origin https://github.com/NIKHILSAINI1801/kafka-web-scanner.git
git push -u origin main
```

Authenticate with GitHub's normal sign-in flow (browser or the GitHub CLI `gh auth login`).
Never paste access tokens into source files, documentation, issues or screenshots.

### Publishing to PyPI (optional, only after the steps above)

1. Check the distribution name `kafka-web-scanner` is free on PyPI **before** announcing it.
   Name availability was not verified when this project was prepared.
2. Prefer *trusted publishing*: create the project on PyPI, add this repository and a
   dedicated release workflow as a trusted publisher, and protect the workflow with a GitHub
   environment that requires approval. Do not publish on every push.
3. After publishing, verify `pip install kafka-web-scanner` in a clean environment before
   documenting it as available.
