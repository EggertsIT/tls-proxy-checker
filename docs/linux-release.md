# Linux Release Process

The Linux build uses the official PyPA
[`manylinux2014`](https://github.com/pypa/manylinux#manylinux2014-centos-7-based-glibc-217)
image for each architecture. `scripts/run_linux_release_build.sh` pins each
image by digest. The release build rejects any bundled ELF file that imports
a GLIBC symbol newer than 2.17.

The older runtime gives the linker access to the glibc symbols in the target
version.

## Compatibility Contract

- Use x86-64 or ARM64 (`aarch64`).
- Use glibc 2.17 or newer.
- The standalone executable includes Python.
- The build uses a pinned Astral CPython 3.13 distribution with a shared
  `libpython`. The build verifies the SHA-256 digest.
- Alpine and other musl-only systems require a glibc runtime.

Linux x86-64 release `v0.4.1` used Ubuntu 22.04 and requires glibc 2.35.
Version `v0.4.2` introduced the glibc 2.17 build. ARM64 uses the same limit.
Your distribution vendor determines its maintenance and security support.

## Build Locally

Install Docker on the host. If the target and host architectures differ,
enable Docker emulation for the target platform.

```bash
bash scripts/run_linux_release_build.sh          # x86-64 (linux/amd64)
bash scripts/run_linux_release_build.sh arm64    # ARM64 (linux/arm64)
```

The wrapper runs with the host user's numeric UID and GID, drops Linux
capabilities, disables privilege escalation, and mounts the repository into
the pinned build image. A file lock limits each checkout to one build at a
time. The inner build verifies the separately pinned CPython archive before
running tests, Bandit, pip-audit, PyInstaller, CLI smoke tests, and the GLIBC
symbol audit. It writes these files to `release-assets/`. Each checksum file
lists the files from the most recent build for that architecture.

| File | x86-64 | ARM64 |
| --- | --- | --- |
| Executable | `tls-proxy-checker-linux-x86_64` | `tls-proxy-checker-linux-aarch64` |
| Archive | `tls-proxy-checker-VERSION-linux-x86_64.tar.gz` | `tls-proxy-checker-VERSION-linux-aarch64.tar.gz` |
| Checksums | `SHA256SUMS` | `SHA256SUMS-linux-aarch64` |
| Build metadata | `BUILDINFO.json` | `BUILDINFO-linux-aarch64.json` |
| GLIBC report | `glibc-requirements.json` | `glibc-requirements-linux-aarch64.json` |
| SBOM | `tls-proxy-checker-VERSION.sbom.cdx.json` | `tls-proxy-checker-VERSION-linux-aarch64.sbom.cdx.json` |

Run these commands from the repository root to check the ARM64 build.

```bash
cat release-assets/glibc-requirements-linux-aarch64.json
(cd release-assets && sha256sum --check SHA256SUMS-linux-aarch64)
./release-assets/tls-proxy-checker-linux-aarch64 --version
```

Run the executable on a Linux system with the applicable architecture.

## CI And Releases

CI runs the build and a smoke test on a native Linux runner for each
architecture. The release workflow verifies the signature on the version tag,
builds each architecture, and attests its files. It verifies the checksums
again before it publishes both builds in one GitHub release.

When you update a manylinux image digest, verify it against the upstream image
for that architecture. Review the upstream change and check the CI audit of
the bundled ELF files. Update each standalone CPython URL and SHA-256 digest
together from the same upstream release asset.
