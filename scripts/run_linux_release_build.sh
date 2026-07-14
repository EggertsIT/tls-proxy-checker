#!/usr/bin/env bash
set -euo pipefail

readonly BUILD_IMAGE_REPOSITORY="quay.io/pypa/manylinux2014_x86_64"
readonly BUILD_IMAGE_DIGEST="sha256:35baef377f64c2ae2e7ed647917ecd090c50f6e8b06fd605012661c2e954cc92"
readonly BUILD_IMAGE="${BUILD_IMAGE_REPOSITORY}@${BUILD_IMAGE_DIGEST}"
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for the glibc 2.17 Linux build" >&2
  exit 1
fi

docker run --rm --pull=always --platform linux/amd64 \
  --user "$(id -u):$(id -g)" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --volume "${ROOT}:/workspace" \
  --workdir /workspace \
  --env HOME=/tmp/build-home \
  --env "GITHUB_SHA=${GITHUB_SHA:-}" \
  --env "RELEASE_TAG=${RELEASE_TAG:-}" \
  "${BUILD_IMAGE}" \
  bash scripts/build_linux_release.sh
