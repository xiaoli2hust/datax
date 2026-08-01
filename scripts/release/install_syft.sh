#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: install_syft.sh <destination>" >&2
  exit 64
fi

destination="$1"
syft_version="1.50.0"
archive_name="syft_${syft_version}_linux_amd64.tar.gz"
expected_sha256="bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788"
download_url="https://github.com/anchore/syft/releases/download/v${syft_version}/${archive_name}"
temporary_directory="$(mktemp -d)"

cleanup() {
  rm -f "${temporary_directory}/${archive_name}" "${temporary_directory}/syft"
  rmdir "${temporary_directory}"
}
trap cleanup EXIT

if [[ -e "${destination}" ]]; then
  echo "Syft destination already exists" >&2
  exit 73
fi
curl --proto '=https' --tlsv1.2 --location --fail --silent --show-error \
  --output "${temporary_directory}/${archive_name}" \
  "${download_url}"
actual_sha256="$(
  sha256sum "${temporary_directory}/${archive_name}" |
    awk '{print $1}'
)"
if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
  echo "Syft archive checksum verification failed" >&2
  exit 65
fi
tar -xzf "${temporary_directory}/${archive_name}" \
  -C "${temporary_directory}" \
  syft
if [[ ! -f "${temporary_directory}/syft" || -L "${temporary_directory}/syft" ]]; then
  echo "downloaded Syft executable is not a regular file" >&2
  exit 65
fi
install -m 0755 "${temporary_directory}/syft" "${destination}"
