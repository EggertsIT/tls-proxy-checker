#!/usr/bin/env bash
set -euo pipefail

architecture="${1-x86_64}"
case "${architecture}" in
  x86_64)
    metadata_suffix=""
    readonly PYTHON_DISTRIBUTION_SHA256="459ed79967acc207bef2ff5124dac35d74d5108528e37b15395d14e2922f2c92"
    ;;
  aarch64)
    metadata_suffix="-linux-aarch64"
    readonly PYTHON_DISTRIBUTION_SHA256="e931d7a393f54902503f8745ceb35420e7dd50a067e78e5f45c71404f7a15b30"
    ;;
  *)
    echo "unsupported Linux release architecture: ${architecture}" >&2
    exit 2
    ;;
esac

readonly PYTHON_DISTRIBUTION_RELEASE="20260623"
readonly PYTHON_DISTRIBUTION_ASSET="cpython-3.13.14%2B${PYTHON_DISTRIBUTION_RELEASE}-${architecture}-unknown-linux-gnu-install_only_stripped.tar.gz"
readonly PYTHON_DISTRIBUTION_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_DISTRIBUTION_RELEASE}/${PYTHON_DISTRIBUTION_ASSET}"
readonly PYTHON_ARCHIVE="/tmp/cpython-linux-${architecture}.tar.gz"
readonly BASE_PYTHON="/tmp/python/bin/python3"
readonly BUILD_VENV="/tmp/tls-proxy-checker-build"
readonly MAXIMUM_GLIBC="2.17"
readonly OUTPUT_DIRECTORY="${PWD}/release-assets"

build_architecture="$(uname -m)"
if [[ "${build_architecture}" != "${architecture}" ]]; then
  echo "expected ${architecture} build image, found ${build_architecture}" >&2
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

# Both architectures use the same PyInstaller paths in a local checkout.
mkdir -p "${OUTPUT_DIRECTORY}"
exec 9>"${OUTPUT_DIRECTORY}/.build.lock"
flock --exclusive 9

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

binary="tls-proxy-checker-linux-${architecture}"
archive="tls-proxy-checker-${version}-linux-${architecture}.tar.gz"
sbom="tls-proxy-checker-${version}${metadata_suffix}.sbom.cdx.json"
buildinfo="BUILDINFO${metadata_suffix}.json"
glibc_report="glibc-requirements${metadata_suffix}.json"
checksums="SHA256SUMS${metadata_suffix}"
artifacts=("${binary}" "${archive}" "${sbom}" "${buildinfo}" "${glibc_report}")

stage="$(mktemp -d "${OUTPUT_DIRECTORY}/.build-${architecture}.XXXXXX")"
trap 'rm -rf -- "${stage}"' EXIT
mkdir "${stage}/package"
install -m 0755 dist/tls-proxy-checker "${stage}/${binary}"
install -m 0755 dist/tls-proxy-checker "${stage}/package/tls-proxy-checker"
cp \
  README.md CHANGELOG.md LICENSE NOTICE THIRD_PARTY_NOTICES.md \
  "${stage}/package/"
python scripts/collect_licenses.py "${stage}/package/licenses"
python scripts/check_glibc.py \
  dist-audit/tls-proxy-checker-audit \
  --maximum "${MAXIMUM_GLIBC}" \
  --json >"${stage}/${glibc_report}"
cat "${stage}/${glibc_report}"
python -m pip_audit \
  --format cyclonedx-json \
  --output "${stage}/${sbom}"
python scripts/build_release_metadata.py \
  --binary "${stage}/${binary}" \
  --glibc-report "${stage}/${glibc_report}" \
  --python-distribution-url "${PYTHON_DISTRIBUTION_URL}" \
  --python-distribution-sha256 "${PYTHON_DISTRIBUTION_SHA256}" \
  --output "${stage}/${buildinfo}"

tar -C "${stage}/package" -czf "${stage}/${archive}" .
chmod -R a+rX "${stage}" dist dist-audit build build-audit
(
  cd "${stage}"
  sha256sum "${artifacts[@]}" >"${checksums}"
  chmod a+r "${checksums}"
  mv -- "${artifacts[@]}" "${checksums}" "${OUTPUT_DIRECTORY}/"
)
