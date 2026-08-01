#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: generate_sboms.sh <syft-path> <evidence-directory>" >&2
  exit 64
fi

syft_path="$1"
evidence_directory="$2"
script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${script_directory}/../.." && pwd)"
images_file="${evidence_directory}/images.release.env"
context_file="${evidence_directory}/release-context.json"
sbom_directory="${evidence_directory}/sbom"
tool_directory="${evidence_directory}/toolchain"
source_snapshot_directory=""

cleanup() {
  if [[ -n "${source_snapshot_directory}" ]]; then
    rm -rf -- "${source_snapshot_directory}"
  fi
}
trap cleanup EXIT

if [[ ! -x "${syft_path}" || -L "${syft_path}" ]]; then
  echo "Syft must be an executable regular file" >&2
  exit 66
fi
if [[ ! -f "${images_file}" || -L "${images_file}" ]]; then
  echo "immutable image lock is missing" >&2
  exit 66
fi
if [[ ! -f "${context_file}" || -L "${context_file}" ]]; then
  echo "release context is missing" >&2
  exit 66
fi
mkdir -p "${sbom_directory}" "${tool_directory}"

source_version="$(
  python3 - "${context_file}" <<'PY'
import json
import re
import sys
from pathlib import Path

document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
commit = document.get("git_commit")
if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
    raise SystemExit("release context has an invalid git commit")
print(commit)
PY
)"
"${syft_path}" version -o json > "${tool_directory}/syft-version.json"
source_snapshot_directory="$(mktemp -d)"
git -C "${repository_root}" archive --format=tar "${source_version}" \
  | tar --extract --file=- --directory="${source_snapshot_directory}"
timeout --foreground --kill-after=30s 15m \
  "${syft_path}" scan "dir:${source_snapshot_directory}" \
  --source-name "xiaoli2hust/datax" \
  --source-version "${source_version}" \
  --output "spdx-json=${sbom_directory}/source.spdx.json"

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

for component in postgres api egress_guard worker web; do
  key="${image_keys[${component}]}"
  repository="${image_repositories[${component}]}"
  mapfile -t values < <(sed -n "s/^${key}=//p" "${images_file}")
  if [[ "${#values[@]}" -ne 1 ]] \
    || [[ "${values[0]%%@*}" != "${repository}" ]] \
    || [[ ! "${values[0]}" =~ ^[^@]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "invalid immutable image reference for ${component}" >&2
    exit 65
  fi
  timeout --foreground --kill-after=30s 15m \
    "${syft_path}" scan "registry:${values[0]}" \
    --platform "linux/amd64" \
    --output "spdx-json=${sbom_directory}/${component}.image.spdx.json"
done

python3 - \
  "${sbom_directory}" \
  "${images_file}" \
  "${context_file}" \
  "${evidence_directory}/sbom-index.json" <<'PY'
import json
import re
import sys
from pathlib import Path

sbom_root = Path(sys.argv[1])
images_file = Path(sys.argv[2])
context_file = Path(sys.argv[3])
output = Path(sys.argv[4])
image_keys = {
    "postgres": "DES_POSTGRES_IMAGE",
    "api": "DES_API_IMAGE",
    "egress_guard": "DES_EGRESS_GUARD_IMAGE",
    "worker": "DES_WORKER_IMAGE",
    "web": "DES_WEB_IMAGE",
}
image_repositories = {
    "postgres": "postgres",
    "api": "ghcr.io/xiaoli2hust/datax-studio-api",
    "egress_guard": "ghcr.io/xiaoli2hust/datax-studio-egress-guard",
    "worker": "ghcr.io/xiaoli2hust/datax-studio-worker",
    "web": "ghcr.io/xiaoli2hust/datax-studio-web",
}
image_values = {}
for raw_line in images_file.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    key, separator, value = line.partition("=")
    if separator != "=" or key in image_values:
        raise SystemExit("images.release.env is not canonical")
    image_values[key] = value
if set(image_values) != set(image_keys.values()):
    raise SystemExit("images.release.env is incomplete")
for component, key in image_keys.items():
    pattern = rf"{re.escape(image_repositories[component])}@sha256:[0-9a-f]{{64}}"
    if re.fullmatch(pattern, image_values[key]) is None:
        raise SystemExit(f"{key} is not an allowlisted immutable reference")
context = json.loads(context_file.read_text(encoding="utf-8"))
commit = context.get("git_commit")
if not isinstance(commit, str):
    raise SystemExit("release context is missing its git commit")

expected_files = {"source.spdx.json"} | {
    f"{component}.image.spdx.json" for component in image_keys
}
actual_files = {path.name for path in sbom_root.glob("*.spdx.json")}
if actual_files != expected_files:
    raise SystemExit("the generated SBOM file set is incomplete or unexpected")

entries = []
for path in sorted(sbom_root.glob("*.spdx.json")):
    with path.open(encoding="utf-8") as stream:
        document = json.load(stream)
    if document.get("spdxVersion") != "SPDX-2.3":
        raise SystemExit(f"{path.name} is not an SPDX 2.3 document")
    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        raise SystemExit(f"{path.name} contains no discovered packages")
    document_name = document.get("name")
    if not isinstance(document_name, str) or not document_name:
        raise SystemExit(f"{path.name} has no SPDX document name")
    if path.name == "source.spdx.json":
        subject = {
            "kind": "source",
            "repository": "xiaoli2hust/datax",
            "git_commit": commit,
        }
    else:
        component = path.name.removesuffix(".image.spdx.json")
        subject = {
            "kind": "container_image",
            "component": component,
            "immutable_reference": image_values[image_keys[component]],
            "platform": "linux/amd64",
        }
    entries.append(
        {
            "file": f"sbom/{path.name}",
            "package_count": len(packages),
            "spdx_document_name": document_name,
            "subject": subject,
        }
    )
output.write_text(
    json.dumps(
        {
            "schema_version": "1.0",
            "generator": "syft",
            "entries": entries,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY
