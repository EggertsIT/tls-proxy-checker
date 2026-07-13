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

```powershell
$Signature = Get-AuthenticodeSignature .\dist\tls-proxy-checker.exe
$Signature | Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
if ($Signature.Status -ne "Valid") { throw "Authenticode signature validation failed" }

.\dist\tls-proxy-checker.exe --version
.\dist\tls-proxy-checker.exe --help | Out-Null

$Version = (python -c "from tls_proxy_checker import __version__; print(__version__)")
$Stage = "release\windows-x86_64"
New-Item -ItemType Directory -Force $Stage | Out-Null
Copy-Item .\dist\tls-proxy-checker.exe "$Stage\tls-proxy-checker.exe"
Copy-Item README.md, CHANGELOG.md, LICENSE, NOTICE, THIRD_PARTY_NOTICES.md $Stage
Compress-Archive "$Stage\*" "release\tls-proxy-checker-$Version-windows-x86_64.zip" -Force
Copy-Item .\dist\tls-proxy-checker.exe release\tls-proxy-checker-windows-x86_64.exe
```

Generate lowercase SHA-256 entries for the platform-specific executable and
ZIP. The file must use LF line endings so `sha256sum --check` works on Linux:

```powershell
$Files = @(
    "tls-proxy-checker-windows-x86_64.exe",
    "tls-proxy-checker-$Version-windows-x86_64.zip"
)
$Lines = foreach ($File in $Files) {
    $Hash = (Get-FileHash "release\$File" -Algorithm SHA256).Hash.ToLowerInvariant()
    "$Hash  $File"
}
[IO.File]::WriteAllText(
    "release\SHA256SUMS-windows-x86_64.txt",
    ($Lines -join "`n") + "`n",
    [Text.UTF8Encoding]::new($false)
)
```

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
