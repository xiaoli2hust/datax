#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: build_and_lock_images.sh <version> <commit-sha> <evidence-directory>" >&2
  exit 64
fi

version="$1"
commit_sha="$2"
evidence_directory="$3"
script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${script_directory}/../.." && pwd)"

if [[ ! "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "invalid release version" >&2
  exit 65
fi
if [[ ! "${commit_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid release commit" >&2
  exit 65
fi
if [[ ! -d "${evidence_directory}" || -L "${evidence_directory}" ]]; then
  echo "evidence directory must already exist and must not be a symlink" >&2
  exit 66
fi

metadata_directory="${evidence_directory}/image-build-metadata"
inspect_directory="${evidence_directory}/image-manifests"
toolchain_directory="${evidence_directory}/toolchain"
mkdir -p \
  "${metadata_directory}" \
  "${inspect_directory}" \
  "${toolchain_directory}"

declare -A release_references

docker version --format '{{json .}}' \
  > "${toolchain_directory}/docker-version.json"
docker buildx version \
  > "${toolchain_directory}/docker-buildx-version.txt"
docker buildx inspect \
  > "${toolchain_directory}/docker-buildx-builder.txt"

assert_single_linux_amd64_image() {
  local manifest_path="$1"
  local component="$2"
  python3 - "${manifest_path}" "${component}" <<'PY'
import json
import sys

path, component = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    document = json.load(stream)
manifests = document.get("manifests")
if not isinstance(manifests, list) or not manifests:
    raise SystemExit(f"{component} did not publish a platform manifest index")
runnable = []
for descriptor in manifests:
    if not isinstance(descriptor, dict):
        raise SystemExit(f"{component} contains a malformed manifest descriptor")
    annotations = descriptor.get("annotations") or {}
    platform = descriptor.get("platform") or {}
    if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
        if (
            platform.get("os") != "unknown"
            or platform.get("architecture") != "unknown"
        ):
            raise SystemExit(
                f"{component} attestation descriptor has an unexpected platform"
            )
        continue
    runnable.append(platform)
if len(runnable) != 1:
    raise SystemExit(f"{component} must contain exactly one runnable image")
platform = runnable[0]
if (
    platform.get("os") != "linux"
    or platform.get("architecture") != "amd64"
    or platform.get("variant") not in (None, "")
):
    raise SystemExit(f"{component} runnable image is not exactly linux/amd64")
PY
}

assert_contains_linux_amd64_image() {
  local manifest_path="$1"
  python3 - "${manifest_path}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    document = json.load(stream)
manifests = document.get("manifests")
if not isinstance(manifests, list):
    raise SystemExit("pinned PostgreSQL digest is not a platform manifest index")
matches = [
    descriptor
    for descriptor in manifests
    if isinstance(descriptor, dict)
    and isinstance(descriptor.get("platform"), dict)
    and descriptor["platform"].get("os") == "linux"
    and descriptor["platform"].get("architecture") == "amd64"
]
if len(matches) != 1:
    raise SystemExit(
        "pinned PostgreSQL digest must contain exactly one linux/amd64 image"
    )
PY
}

build_image() {
  local component="$1"
  local repository="$2"
  local dockerfile="$3"
  local context="$4"
  local metadata_path="${metadata_directory}/${component}.json"
  local tag="${repository}:candidate-${version}-${commit_sha:0:12}"

  docker buildx build \
    --file "${repository_root}/${dockerfile}" \
    --platform "linux/amd64" \
    --pull \
    --push \
    --provenance=mode=max \
    --label "org.opencontainers.image.revision=${commit_sha}" \
    --label "org.opencontainers.image.version=${version}" \
    --label "org.opencontainers.image.source=https://github.com/xiaoli2hust/datax" \
    --label "io.datax.enterprise-studio.release-kind=candidate" \
    --tag "${tag}" \
    --metadata-file "${metadata_path}" \
    "${repository_root}/${context}"

  local digest
  digest="$(
    python3 - "${metadata_path}" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    metadata = json.load(stream)
digest = metadata.get("containerimage.digest")
if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
    raise SystemExit("buildx metadata did not contain an immutable image digest")
print(digest)
PY
  )"
  local immutable_reference="${repository}@${digest}"
  docker buildx imagetools inspect "${immutable_reference}" --raw \
    > "${inspect_directory}/${component}.json"
  assert_single_linux_amd64_image \
    "${inspect_directory}/${component}.json" \
    "${component}"
  release_references["${component}"]="${immutable_reference}"
}

build_image \
  "api" \
  "ghcr.io/xiaoli2hust/datax-studio-api" \
  "backend/Dockerfile" \
  "backend"
build_image \
  "egress_guard" \
  "ghcr.io/xiaoli2hust/datax-studio-egress-guard" \
  "deploy/windows/egress-guard/Dockerfile" \
  "deploy/windows/egress-guard"
build_image \
  "worker" \
  "ghcr.io/xiaoli2hust/datax-studio-worker" \
  "backend/Dockerfile.worker" \
  "."
build_image \
  "web" \
  "ghcr.io/xiaoli2hust/datax-studio-web" \
  "frontend/Dockerfile" \
  "."

postgres_source="${repository_root}/deploy/windows/images.dev.env"
mapfile -t postgres_lines < <(
  grep -E '^DES_POSTGRES_IMAGE=postgres:15\.18-alpine3\.24@sha256:[0-9a-f]{64}$' \
    "${postgres_source}"
)
if [[ "${#postgres_lines[@]}" -ne 1 ]]; then
  echo "the repository must contain exactly one pinned PostgreSQL 15.18 digest" >&2
  exit 65
fi
postgres_pinned="${postgres_lines[0]#DES_POSTGRES_IMAGE=}"
postgres_digest="${postgres_pinned##*@}"
postgres_reference="postgres@${postgres_digest}"
docker buildx imagetools inspect "${postgres_pinned}" --raw \
  > "${inspect_directory}/postgres.json"
assert_contains_linux_amd64_image "${inspect_directory}/postgres.json"
release_references["postgres"]="${postgres_reference}"

images_file="${evidence_directory}/images.release.env"
{
  echo "# Candidate-only digest lock generated from commit ${commit_sha}."
  echo "# Every value is immutable; tags are intentionally excluded."
  echo "DES_POSTGRES_IMAGE=${release_references[postgres]}"
  echo "DES_API_IMAGE=${release_references[api]}"
  echo "DES_EGRESS_GUARD_IMAGE=${release_references[egress_guard]}"
  echo "DES_WORKER_IMAGE=${release_references[worker]}"
  echo "DES_WEB_IMAGE=${release_references[web]}"
} > "${images_file}"

python3 - \
  "${version}" \
  "${commit_sha}" \
  "${images_file}" \
  "${evidence_directory}/image-lock.json" <<'PY'
import json
import re
import sys
from pathlib import Path

version, commit, source_name, output_name = sys.argv[1:]
repositories = {
    "DES_POSTGRES_IMAGE": "postgres",
    "DES_API_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-api",
    "DES_EGRESS_GUARD_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-egress-guard",
    "DES_WORKER_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-worker",
    "DES_WEB_IMAGE": "ghcr.io/xiaoli2hust/datax-studio-web",
}
values: dict[str, str] = {}
for raw_line in Path(source_name).read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    key, separator, value = line.partition("=")
    if separator != "=" or key not in repositories or key in values:
        raise SystemExit("images.release.env is not canonical")
    expected = rf"{re.escape(repositories[key])}@sha256:[0-9a-f]{{64}}"
    if re.fullmatch(expected, value) is None:
        raise SystemExit(f"{key} is not an allowlisted immutable reference")
    values[key] = value
if set(values) != set(repositories):
    raise SystemExit("images.release.env is incomplete")
document = {
    "schema_version": "1.0",
    "candidate_only": True,
    "git_commit": commit,
    "version": version,
    "platform": "linux/amd64",
    "images": {
        "postgres": values["DES_POSTGRES_IMAGE"],
        "api": values["DES_API_IMAGE"],
        "egress_guard": values["DES_EGRESS_GUARD_IMAGE"],
        "worker": values["DES_WORKER_IMAGE"],
        "web": values["DES_WEB_IMAGE"],
    },
}
Path(output_name).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
