#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: install_osv_scanner.sh <destination>" >&2
  exit 64
fi

destination="$1"
osv_version="2.4.0"
asset_name="osv-scanner_linux_amd64"
expected_sha256="15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0"
download_url="https://github.com/google/osv-scanner/releases/download/v${osv_version}/${asset_name}"
temporary_directory="$(mktemp -d)"
download_path="${temporary_directory}/${asset_name}"

cleanup() {
  rm -f "${download_path}"
  rmdir "${temporary_directory}"
}
trap cleanup EXIT

if [[ -e "${destination}" ]]; then
  echo "OSV-Scanner destination already exists" >&2
  exit 73
fi

curl --proto '=https' --tlsv1.2 --location --fail --silent --show-error \
  --output "${download_path}" \
  "${download_url}"
actual_sha256="$(
  sha256sum "${download_path}" |
    awk '{print $1}'
)"
if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
  echo "OSV-Scanner checksum verification failed" >&2
  exit 65
fi
if [[ ! -f "${download_path}" || -L "${download_path}" ]]; then
  echo "downloaded OSV-Scanner executable is not a regular file" >&2
  exit 65
fi
install -m 0755 "${download_path}" "${destination}"
