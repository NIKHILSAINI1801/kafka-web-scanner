# Contributing to KAFKA

Thank you for helping. KAFKA is a small educational project with a strict scope.

## Ground rules

* **Stay passive.** Contributions that add exploitation, payload injection, brute force,
  credential collection, login automation, form submission, crawling, directory brute-forcing,
  stealth/evasion, rate-limit bypass or automatic target changes will not be merged.
* **Never weaken a safeguard** (URL validation, address blocking, authorization prompt,
  timeouts, response cap, TLS verification, redirect blocking, secret handling) without a
  documented, tested reason.
* **No secrets or scan output** in the repository: no tokens, cookie values, reports,
  history databases or personal data.

## Workflow

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest -q
ruff check .
ruff format .
```

1. Open an issue (or comment on one) before large changes.
2. Branch from `main`; keep commits focused.
3. Add tests. Scanner modules need unit tests; behaviour touching the network needs an
   integration test against the local test server (never a real website).
4. Update `CHANGELOG.md` and the docs when behaviour changes.
5. Open a pull request using the template. CI must pass.

## Adding a scanner module

See "Adding a module" in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Licensing

By contributing you agree that your contribution is licensed under the project's license
(see `LICENSE`). If you contribute on behalf of an institution, make sure you are allowed to.
