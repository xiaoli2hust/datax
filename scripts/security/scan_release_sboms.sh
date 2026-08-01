#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: scan_release_sboms.sh <osv-scanner-path> <grype-path> <evidence-directory>" >&2
  exit 64
fi

osv_scanner_path="$1"
grype_path="$2"
evidence_directory="$3"
script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
application_evaluator="${script_directory}/evaluate_osv_report.py"
os_evaluator="${script_directory}/evaluate_grype_os_report.py"
application_exceptions_source="${script_directory}/osv-application-exceptions.json"
os_exceptions_source="${script_directory}/grype-os-exceptions.json"
sbom_directory="${evidence_directory}/sbom"
report_directory="${evidence_directory}/vulnerability-reports"
policy_directory="${evidence_directory}/vulnerability-policies"
toolchain_directory="${evidence_directory}/toolchain"
images_file="${evidence_directory}/images.release.env"

for executable in \
  "${osv_scanner_path}" \
  "${grype_path}" \
  "${application_evaluator}" \
  "${os_evaluator}"
do
  if [[ ! -x "${executable}" || ! -f "${executable}" || -L "${executable}" ]]; then
    echo "security scanner or evaluator must be an executable regular file: ${executable}" >&2
    exit 66
  fi
done
for required_file in \
  "${application_exceptions_source}" \
  "${os_exceptions_source}" \
  "${images_file}"
do
  if [[ ! -f "${required_file}" || -L "${required_file}" ]]; then
    echo "required release security input is missing or unsafe: ${required_file}" >&2
    exit 66
  fi
done
if [[ ! -d "${sbom_directory}" || -L "${sbom_directory}" ]]; then
  echo "release SBOM directory is missing" >&2
  exit 66
fi

expected_sboms=(
  "source.spdx.json"
  "postgres.image.spdx.json"
  "api.image.spdx.json"
  "egress_guard.image.spdx.json"
  "worker.image.spdx.json"
  "web.image.spdx.json"
)
for sbom_name in "${expected_sboms[@]}"; do
  sbom_path="${sbom_directory}/${sbom_name}"
  if [[ ! -f "${sbom_path}" || -L "${sbom_path}" ]]; then
    echo "required release SBOM is missing or unsafe: ${sbom_name}" >&2
    exit 66
  fi
done

mkdir -p \
  "${report_directory}" \
  "${policy_directory}" \
  "${toolchain_directory}"
application_exceptions="${policy_directory}/osv-application-exceptions.json"
os_exceptions="${policy_directory}/grype-os-exceptions.json"
for destination in "${application_exceptions}" "${os_exceptions}"; do
  if [[ -e "${destination}" || -L "${destination}" ]]; then
    echo "release vulnerability policy evidence already exists: ${destination}" >&2
    exit 73
  fi
done
install --mode 0444 "${application_exceptions_source}" "${application_exceptions}"
install --mode 0444 "${os_exceptions_source}" "${os_exceptions}"

"${osv_scanner_path}" --version \
  > "${toolchain_directory}/osv-scanner-version.txt"
"${grype_path}" version \
  > "${toolchain_directory}/grype-version.txt"

image_components=(postgres api egress_guard worker web)
declare -A image_keys=(
  [postgres]="DES_POSTGRES_IMAGE"
  [api]="DES_API_IMAGE"
  [egress_guard]="DES_EGRESS_GUARD_IMAGE"
  [worker]="DES_WORKER_IMAGE"
  [web]="DES_WEB_IMAGE"
)
declare -A image_repositories=(
  [postgres]="postgres"
  [api]="ghcr.io/xiaoli2hust/datax-studio-api"
  [egress_guard]="ghcr.io/xiaoli2hust/datax-studio-egress-guard"
  [worker]="ghcr.io/xiaoli2hust/datax-studio-worker"
  [web]="ghcr.io/xiaoli2hust/datax-studio-web"
)
declare -A image_references=()

python3 - "${images_file}" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected = {
    "DES_POSTGRES_IMAGE": "postgres",
    "DES_API_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-api",
    "DES_EGRESS_GUARD_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-egress-guard",
    "DES_WORKER_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-worker",
    "DES_WEB_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-web",
}
values = {}
for raw_line in path.read_text(encoding="utf-8").splitlines():
    if not raw_line or raw_line.startswith("#"):
        continue
    if raw_line != raw_line.strip():
        raise SystemExit("release image lock contains surrounding whitespace")
    key, separator, value = raw_line.partition("=")
    if separator != "=" or not key or key in values:
        raise SystemExit("release image lock is not canonical")
    values[key] = value
if set(values) != set(expected):
    raise SystemExit("release image lock has an unexpected key set")
for key, repository in expected.items():
    if re.fullmatch(rf"{re.escape(repository)}@sha256:[0-9a-f]{{64}}", values[key]) is None:
        raise SystemExit(f"release image lock has an invalid {key}")
PY

for component in "${image_components[@]}"; do
  key="${image_keys[${component}]}"
  repository="${image_repositories[${component}]}"
  mapfile -t values < <(sed -n "s/^${key}=//p" "${images_file}")
  if [[ "${#values[@]}" -ne 1 ]] \
    || [[ "${values[0]%%@*}" != "${repository}" ]] \
    || [[ ! "${values[0]}" =~ ^[^@]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "release image lock has an invalid ${key}" >&2
    exit 65
  fi
  image_references["${component}"]="${values[0]}"
done

osv_image_reports=()
for sbom_name in "${expected_sboms[@]}"; do
  report_name="${sbom_name%.spdx.json}.osv.json"
  report_path="${report_directory}/${report_name}"
  if [[ -e "${report_path}" || -L "${report_path}" ]]; then
    echo "OSV report already exists: ${report_name}" >&2
    exit 73
  fi
  set +e
  timeout --foreground --kill-after=30s 15m \
    "${osv_scanner_path}" scan source \
    --sbom "${sbom_directory}/${sbom_name}" \
    --format json \
    --verbosity warn \
    --output-file "${report_path}"
  scanner_status=$?
  set -e
  if [[ "${scanner_status}" -ne 0 && "${scanner_status}" -ne 1 ]]; then
    echo "OSV-Scanner failed to produce a complete report for ${sbom_name}" >&2
    exit "${scanner_status}"
  fi
  if [[ ! -s "${report_path}" || -L "${report_path}" ]]; then
    echo "OSV-Scanner produced an unsafe or empty report for ${sbom_name}" >&2
    exit 65
  fi
  if [[ "${sbom_name}" != "source.spdx.json" ]]; then
    osv_image_reports+=("${report_path}")
  fi
done

combined_osv_report="${report_directory}/runtime-images.osv.json"
python3 - "${combined_osv_report}" "${osv_image_reports[@]}" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
results = []
sources = []
for raw_path in sys.argv[2:]:
    path = Path(raw_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    document_results = document.get("results")
    if not isinstance(document_results, list):
        raise SystemExit(f"OSV report has no results array: {path.name}")
    results.extend(document_results)
    sources.append(path.name)
output.write_text(
    json.dumps(
        {
            "results": results,
            "release_evidence": {
                "kind": "combined_runtime_image_osv_report",
                "source_reports": sources,
            },
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY

application_policy_status=0
set +e
python3 "${application_evaluator}" \
  --report "${combined_osv_report}" \
  --exceptions "${application_exceptions}" \
  --output "${report_directory}/runtime-images.application-policy.json"
application_policy_status=$?
set -e

for component in "${image_components[@]}"; do
  report_path="${report_directory}/${component}.image.grype.json"
  if [[ -e "${report_path}" || -L "${report_path}" ]]; then
    echo "Grype report already exists for ${component}" >&2
    exit 73
  fi
  timeout --foreground --kill-after=30s 15m \
    "${grype_path}" \
    "registry:${image_references[${component}]}" \
    --platform "linux/amd64" \
    --output json \
    --file "${report_path}"
  if [[ ! -s "${report_path}" || -L "${report_path}" ]]; then
    echo "Grype produced an unsafe or empty report for ${component}" >&2
    exit 65
  fi
done
"${grype_path}" db status --output json \
  > "${toolchain_directory}/grype-db-status.json"

os_policy_status=0
for component in "${image_components[@]}"; do
  set +e
  python3 "${os_evaluator}" \
    --component "${component}" \
    --exceptions "${os_exceptions}" \
    --mode candidate \
    --report "${report_directory}/${component}.image.grype.json" \
    --output "${report_directory}/${component}.image.grype-policy.json"
  evaluator_status=$?
  set -e
  if [[ "${evaluator_status}" -gt "${os_policy_status}" ]]; then
    os_policy_status="${evaluator_status}"
  fi
done

if [[ "${application_policy_status}" -ne 0 ]]; then
  echo "release application dependency policy failed" >&2
  exit "${application_policy_status}"
fi
if [[ "${os_policy_status}" -ne 0 ]]; then
  echo "release distro package policy failed" >&2
  exit "${os_policy_status}"
fi
