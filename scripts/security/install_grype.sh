#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: install_grype.sh <destination>" >&2
  exit 64
fi

destination="$1"
grype_version="0.112.0"
asset_name="grype_${grype_version}_linux_amd64.tar.gz"
expected_sha256="acb14a030010fe9bdb9594b4ae108d9d14ef2f926d936aa0916dc62c89c058ea"
download_url="https://github.com/anchore/grype/releases/download/v${grype_version}/${asset_name}"

if [[ -e "${destination}" || -L "${destination}" ]]; then
  echo "Grype destination already exists" >&2
  exit 73
fi

umask 077
temporary_directory="$(mktemp -d)"
archive_path="${temporary_directory}/${asset_name}"
trap 'rm -rf -- "${temporary_directory}"' EXIT

curl \
  --fail \
  --location \
  --proto '=https' \
  --retry 3 \
  --show-error \
  --silent \
  --tlsv1.2 \
  "${download_url}" \
  --output "${archive_path}"

printf '%s  %s\n' "${expected_sha256}" "${archive_path}" \
  | sha256sum --check --strict --status

tar \
  --extract \
  --file "${archive_path}" \
  --gzip \
  --directory "${temporary_directory}" \
  grype

extracted_path="${temporary_directory}/grype"
if [[ ! -f "${extracted_path}" || -L "${extracted_path}" ]]; then
  echo "downloaded Grype executable is not a regular file" >&2
  exit 65
fi

install --mode 0755 "${extracted_path}" "${destination}"
"${destination}" version >/dev/null
