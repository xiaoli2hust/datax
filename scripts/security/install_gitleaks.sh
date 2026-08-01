#!/usr/bin/env bash
set -euo pipefail

readonly GITLEAKS_VERSION="8.30.1"

usage() {
  printf 'Usage: %s ABSOLUTE_DESTINATION\n' "${0##*/}" >&2
}

if [[ $# -ne 1 || "$1" != /* ]]; then
  usage
  exit 64
fi

readonly destination="$1"
if [[ -e "${destination}" ]]; then
  printf 'Refusing to overwrite existing destination: %s\n' "${destination}" >&2
  exit 73
fi
if [[ ! -d "$(dirname "${destination}")" ]]; then
  printf 'Destination parent does not exist: %s\n' "$(dirname "${destination}")" >&2
  exit 72
fi

case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    readonly archive_name="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    readonly expected_sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    ;;
  Darwin:arm64)
    readonly archive_name="gitleaks_${GITLEAKS_VERSION}_darwin_arm64.tar.gz"
    readonly expected_sha256="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
    ;;
  *)
    printf 'Unsupported Gitleaks bootstrap platform: %s:%s\n' \
      "$(uname -s)" "$(uname -m)" >&2
    exit 69
    ;;
esac

readonly download_url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${archive_name}"
temporary_directory="$(mktemp -d)"
readonly temporary_directory
cleanup() {
  find "${temporary_directory}" -mindepth 1 -delete
  rmdir "${temporary_directory}"
}
trap cleanup EXIT

readonly archive_path="${temporary_directory}/${archive_name}"
curl \
  --fail \
  --location \
  --proto '=https' \
  --silent \
  --show-error \
  --tlsv1.2 \
  --output "${archive_path}" \
  "${download_url}"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "${archive_path}" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual_sha256="$(shasum -a 256 "${archive_path}" | awk '{print $1}')"
else
  printf 'No SHA-256 verification tool is available.\n' >&2
  exit 69
fi
readonly actual_sha256
if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
  printf 'Gitleaks archive SHA-256 mismatch.\n' >&2
  exit 65
fi

tar -xzf "${archive_path}" -C "${temporary_directory}" gitleaks
install -m 0755 "${temporary_directory}/gitleaks" "${destination}"

reported_version="$("${destination}" version)"
readonly reported_version
if [[ "${reported_version}" != "${GITLEAKS_VERSION}" ]]; then
  printf 'Unexpected Gitleaks version: %s\n' "${reported_version}" >&2
  exit 65
fi
