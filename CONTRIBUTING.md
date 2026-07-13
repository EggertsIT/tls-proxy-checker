# Contributing

## Development Setup

Use Python 3.10 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,build]"
python -m pytest
```

Before submitting a pull request, run:

```bash
python -m pytest
python -m bandit -q -r src scripts
python -m pip_audit
python -m build
```

## Change Requirements

- Keep changes focused and add tests for behavior changes.
- Preserve stable finding IDs unless the JSON schema version is incremented.
- Do not commit build output, virtual environments, certificates, keys, scan
  reports, or endpoint data.
- Changes to an inspection profile must cite primary vendor documentation,
  update its review date, and include profile contract tests.
- Live BadSSL checks supplement the deterministic test suite; they are not a
  substitute for local tests because remote endpoints can change.

By submitting a contribution, you confirm that you have the right to provide
it under the Apache License 2.0.
