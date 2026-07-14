#!/usr/bin/env bash
set -euo pipefail

readonly PYTHON_DISTRIBUTION_RELEASE="20260623"
readonly PYTHON_DISTRIBUTION_ASSET="cpython-3.13.14%2B20260623-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
readonly PYTHON_DISTRIBUTION_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_DISTRIBUTION_RELEASE}/${PYTHON_DISTRIBUTION_ASSET}"
readonly PYTHON_DISTRIBUTION_SHA256="459ed79967acc207bef2ff5124dac35d74d5108528e37b15395d14e2922f2c92"
readonly PYTHON_ARCHIVE="/tmp/cpython-linux-x86_64.tar.gz"
readonly BASE_PYTHON="/tmp/python/bin/python3"
readonly BUILD_VENV="/tmp/tls-proxy-checker-build"
readonly MAXIMUM_GLIBC="2.17"
readonly OUTPUT_DIRECTORY="release-assets"

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "the Linux release must be built on x86-64" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to retrieve the pinned CPython distribution" >&2
  exit 1
fi

build_glibc="$(ldd --version | sed -n '1s/.* //p')"
if [[ "${build_glibc}" != "${MAXIMUM_GLIBC}" ]]; then
  echo "expected glibc ${MAXIMUM_GLIBC} build image, found ${build_glibc}" >&2
  exit 1
fi

mkdir -p "${HOME}"
curl --fail --location --retry 3 --silent --show-error \
  --output "${PYTHON_ARCHIVE}" \
  "${PYTHON_DISTRIBUTION_URL}"
printf '%s  %s\n' \
  "${PYTHON_DISTRIBUTION_SHA256}" \
  "${PYTHON_ARCHIVE}" | sha256sum --check --status
tar -xzf "${PYTHON_ARCHIVE}" -C /tmp
if [[ ! -x "${BASE_PYTHON}" || ! -f /tmp/python/lib/libpython3.13.so.1.0 ]]; then
  echo "the pinned CPython distribution is missing its shared library" >&2
  exit 1
fi

"${BASE_PYTHON}" -m venv "${BUILD_VENV}"
export PATH="${BUILD_VENV}/bin:${PATH}"
export TLS_PROXY_CHECKER_PYTHON_DISTRIBUTION_URL="${PYTHON_DISTRIBUTION_URL}"
export TLS_PROXY_CHECKER_PYTHON_DISTRIBUTION_SHA256
python -m pip install --upgrade pip
python -m pip install ".[dev,build]"

version="$(python -c 'from tls_proxy_checker import __version__; print(__version__)')"
release_tag="${RELEASE_TAG:-v${version}}"
python scripts/verify_release_version.py "${release_tag}"

python -m pytest -q
python -m bandit -q -r src scripts
python -m pip_audit

make build
make build-audit
./dist/tls-proxy-checker --version
./dist/tls-proxy-checker --help >/dev/null

rm -rf "${OUTPUT_DIRECTORY}"
mkdir -p "${OUTPUT_DIRECTORY}/package"
install -m 0755 \
  dist/tls-proxy-checker \
  "${OUTPUT_DIRECTORY}/tls-proxy-checker-linux-x86_64"
install -m 0755 \
  dist/tls-proxy-checker \
  "${OUTPUT_DIRECTORY}/package/tls-proxy-checker"
cp \
  README.md CHANGELOG.md LICENSE NOTICE THIRD_PARTY_NOTICES.md \
  "${OUTPUT_DIRECTORY}/package/"
python scripts/collect_licenses.py "${OUTPUT_DIRECTORY}/package/licenses"
python scripts/check_glibc.py \
  dist-audit/tls-proxy-checker-audit \
  --maximum "${MAXIMUM_GLIBC}" \
  --json >"${OUTPUT_DIRECTORY}/glibc-requirements.json"
cat "${OUTPUT_DIRECTORY}/glibc-requirements.json"
python -m pip_audit \
  --format cyclonedx-json \
  --output "${OUTPUT_DIRECTORY}/tls-proxy-checker-${version}.sbom.cdx.json"
python scripts/build_release_metadata.py \
  --binary "${OUTPUT_DIRECTORY}/tls-proxy-checker-linux-x86_64" \
  --glibc-report "${OUTPUT_DIRECTORY}/glibc-requirements.json" \
  --output "${OUTPUT_DIRECTORY}/BUILDINFO.json"

tar -C "${OUTPUT_DIRECTORY}/package" \
  -czf "${OUTPUT_DIRECTORY}/tls-proxy-checker-${version}-linux-x86_64.tar.gz" .
rm -rf "${OUTPUT_DIRECTORY}/package"
(
  cd "${OUTPUT_DIRECTORY}"
  sha256sum \
    tls-proxy-checker-linux-x86_64 \
    tls-proxy-checker-*.tar.gz \
    tls-proxy-checker-*.sbom.cdx.json \
    BUILDINFO.json \
    glibc-requirements.json >SHA256SUMS
)

chmod -R a+rX "${OUTPUT_DIRECTORY}" dist dist-audit build build-audit
