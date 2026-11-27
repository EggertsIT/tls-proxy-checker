#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: bash scripts/run_linux_release_build.sh [x86_64|aarch64|arm64]" >&2
  exit 2
}

if (( $# > 1 )); then
  usage
fi

case "${1-x86_64}" in
  x86_64)
    architecture=x86_64
    platform=linux/amd64
    image_digest=sha256:35baef377f64c2ae2e7ed647917ecd090c50f6e8b06fd605012661c2e954cc92
    ;;
  aarch64|arm64)
    architecture=aarch64
    platform=linux/arm64
    image_digest=sha256:382236bfd11d86894d9792a6fa5286190b8dd3d075a7032284e123c288711e4f
    ;;
  *) usage ;;
esac

readonly BUILD_IMAGE="quay.io/pypa/manylinux2014_${architecture}@${image_digest}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for the glibc 2.17 Linux build" >&2
  exit 1
fi

docker run --rm --pull=always --platform "${platform}" \
  --user "$(id -u):$(id -g)" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --volume "${ROOT}:/workspace" \
  --workdir /workspace \
  --env HOME=/tmp/build-home \
  --env "GITHUB_SHA=${GITHUB_SHA:-}" \
  --env "RELEASE_TAG=${RELEASE_TAG:-}" \
  "${BUILD_IMAGE}" \
  bash scripts/build_linux_release.sh "${architecture}"
