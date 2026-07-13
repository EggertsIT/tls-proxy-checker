# Windows Release Process

Windows binaries are built and signed on a trusted Windows workstation because
the Certum cloud-signing identity is not stored in GitHub Actions.

## Build

Start from a clean checkout of the release tag and use a dedicated virtual
environment:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install ".[dev,build]"
python -m pytest -q
python -m bandit -q -r src scripts
python -m pip_audit
python -m PyInstaller --clean --noconfirm tls-proxy-checker.spec
```

The unsigned output is `dist\tls-proxy-checker.exe`. Sign that file with the
Certum code-signing certificate and an RFC 3161 timestamp before packaging it.
Never commit the executable, signing credentials, or cloud-signing session data.

## Verify And Package

Run the repository packaging script after signing. It verifies the
Authenticode signature and timestamp, confirms the project version, collects
the complete CPython and dependency license texts, creates the ZIP, and writes
lowercase SHA-256 entries with LF line endings:

```powershell
.\scripts\package_windows_release.ps1
```

The output directory contains:

- `tls-proxy-checker-windows-x86_64.exe`
- `tls-proxy-checker-VERSION-windows-x86_64.zip`
- `SHA256SUMS-windows-x86_64.txt`
- A staging directory whose `licenses` folder must contain at least the
  CPython, cryptography, pyOpenSSL, Rich, and PyInstaller license files

## Publish And Validate

Upload the three files to the matching GitHub release without replacing any
existing Linux assets:

```powershell
gh release upload "v$Version" `
  release\tls-proxy-checker-windows-x86_64.exe `
  "release\tls-proxy-checker-$Version-windows-x86_64.zip" `
  release\SHA256SUMS-windows-x86_64.txt `
  --repo EggertsIT/tls-proxy-checker
```

Run the `Verify Windows Release` workflow with the published tag. Publication
is complete only after its Windows-hosted signature and runtime checks pass.
