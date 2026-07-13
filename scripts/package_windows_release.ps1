[CmdletBinding()]
param(
    [string]$Executable = "dist\tls-proxy-checker.exe",
    [string]$OutputDirectory = "release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $Root
try {
    $ExecutablePath = (Resolve-Path $Executable).Path
    $Signature = Get-AuthenticodeSignature $ExecutablePath
    if ($Signature.Status -ne "Valid") {
        throw "Authenticode validation failed: $($Signature.StatusMessage)"
    }
    if (-not $Signature.TimeStamperCertificate) {
        throw "Authenticode signature is not timestamped"
    }

    $Version = (& python -c "from tls_proxy_checker import __version__; print(__version__)" | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $Version) {
        throw "Unable to read the project version"
    }
    & python scripts/verify_release_version.py "v$Version"
    if ($LASTEXITCODE -ne 0) {
        throw "Project version declarations are inconsistent"
    }

    $OutputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $OutputDirectory
    )
    $Stage = Join-Path $OutputRoot "windows-x86_64"
    New-Item -ItemType Directory -Force $OutputRoot | Out-Null
    if (Test-Path $Stage) {
        Remove-Item $Stage -Recurse -Force
    }
    New-Item -ItemType Directory -Force $Stage | Out-Null

    Copy-Item $ExecutablePath (Join-Path $Stage "tls-proxy-checker.exe")
    Copy-Item README.md, CHANGELOG.md, LICENSE, NOTICE, THIRD_PARTY_NOTICES.md $Stage
    & python scripts/collect_licenses.py (Join-Path $Stage "licenses")
    if ($LASTEXITCODE -ne 0) {
        throw "Third-party license collection failed"
    }

    $LicenseFiles = @(Get-ChildItem (Join-Path $Stage "licenses") -File)
    if ($LicenseFiles.Count -lt 10) {
        throw "Expected at least 10 collected license files, found $($LicenseFiles.Count)"
    }

    $Archive = Join-Path $OutputRoot "tls-proxy-checker-$Version-windows-x86_64.zip"
    $Standalone = Join-Path $OutputRoot "tls-proxy-checker-windows-x86_64.exe"
    if (Test-Path $Archive) {
        Remove-Item $Archive -Force
    }
    Compress-Archive (Join-Path $Stage "*") $Archive
    Copy-Item $ExecutablePath $Standalone -Force

    $Artifacts = @($Standalone, $Archive)
    $ChecksumLines = foreach ($Artifact in $Artifacts) {
        $Hash = (Get-FileHash $Artifact -Algorithm SHA256).Hash.ToLowerInvariant()
        "$Hash  $([IO.Path]::GetFileName($Artifact))"
    }
    $ChecksumFile = Join-Path $OutputRoot "SHA256SUMS-windows-x86_64.txt"
    [IO.File]::WriteAllText(
        $ChecksumFile,
        ($ChecksumLines -join "`n") + "`n",
        [Text.UTF8Encoding]::new($false)
    )

    Write-Host "Created signed Windows release package in $OutputRoot"
    $Artifacts + $ChecksumFile | ForEach-Object { Write-Host "  $_" }
}
finally {
    Pop-Location
}
