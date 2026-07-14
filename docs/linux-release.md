# Linux Release Process

Linux x86-64 releases are built in the official PyPA
[`manylinux2014`](https://github.com/pypa/manylinux#manylinux2014-centos-7-based-glibc-217)
image. The image is pinned by digest in
`scripts/run_linux_release_build.sh`, and the release gate rejects any bundled
ELF file that imports a GLIBC symbol newer than 2.17.

Building on an older runtime is essential. Lowering the audit threshold while
continuing to build on Ubuntu 22.04 does not change the symbols imported by the
binary.

## Compatibility Contract

- Architecture: x86-64
- C library: glibc 2.17 or newer
- Python on target: not required
- Build Python: a SHA-256-verified, pinned Astral standalone CPython 3.13
  distribution with a shared `libpython`
- Alpine and other musl-only systems: not supported without a glibc runtime

The GLIBC floor is a binary compatibility statement, not a promise that every
distribution using that GLIBC version is still maintained or secure. Release
`v0.4.1` was built on Ubuntu 22.04 and requires glibc 2.35; the 2.17 contract
applies to Linux binaries built after that release.

## Build Locally

Docker is the only host dependency. On non-x86-64 hosts, Docker must provide
`linux/amd64` emulation.

```bash
bash scripts/run_linux_release_build.sh
```

The wrapper runs with the host user's numeric UID and GID, drops Linux
capabilities, disables privilege escalation, and mounts the repository into
the pinned build image. The inner build verifies the separately pinned CPython
archive before running tests, Bandit, pip-audit, PyInstaller, CLI smoke tests,
and the GLIBC symbol audit before creating:

- `release-assets/tls-proxy-checker-linux-x86_64`
- `release-assets/tls-proxy-checker-VERSION-linux-x86_64.tar.gz`
- `release-assets/SHA256SUMS`
- `release-assets/BUILDINFO.json`
- `release-assets/glibc-requirements.json`
- `release-assets/tls-proxy-checker-VERSION.sbom.cdx.json`

Inspect the compatibility evidence directly:

```bash
cat release-assets/glibc-requirements.json
sha256sum --check release-assets/SHA256SUMS
./release-assets/tls-proxy-checker-linux-x86_64 --version
```

## CI And Releases

The `Linux glibc 2.17` CI job executes the same wrapper on every pull request
and push to `main`. A signed version tag runs the release workflow with the
same script, then smoke-tests the binary on the newer GitHub runner before
attestation and publication.

When updating the manylinux image digest, verify that it is the current digest
for `quay.io/pypa/manylinux2014_x86_64`, review the upstream image change, and
let the compatibility job audit the complete generated ELF inventory before
merging. Treat the standalone CPython URL and digest as a second pinned build
input: update them together from the same upstream release asset.
