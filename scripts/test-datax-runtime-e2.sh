#!/bin/sh
#
# Direct DataX Runtime E2 only. It creates disposable MySQL/PostgreSQL
# fixtures and runs scripts/datax_runtime_e2_runner.py inside a supplied
# Worker image. It does not start product Compose/API/queue/Worker and is
# never product E3 or Windows E4 evidence.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
mysql_image="mysql:8.4@sha256:1d6b6a8fcee8ff758ff151d017f5203cd06792a0e698f0a593c9dfcb14609cf0"
postgres_image="postgres:15.18-alpine3.24@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f"
worker_image=""
timeout_seconds="${DATAX_RUNTIME_E2_TIMEOUT_SECONDS:-180}"
runner_script="$repository_root/scripts/datax_runtime_e2_runner.py"
run_suffix=""
resource_prefix=""
network_name=""
mysql_source=""
mysql_target=""
postgres_source=""
postgres_target=""
worker_container=""
network_id=""
mysql_source_id=""
mysql_target_id=""
postgres_source_id=""
postgres_target_id=""
worker_container_id=""
fixture_password=""
mysql_root_password=""

usage() {
  printf '%s\n' \
    "usage: $0 --worker-image IMAGE" \
    "" \
    "Build the fixed Worker image first, for example:" \
    "  docker build -f backend/Dockerfile.worker -t datax-enterprise-studio-worker:runtime-e2 ." \
    "  $0 --worker-image datax-enterprise-studio-worker:runtime-e2"
}

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --worker-image)
      [ "$#" -ge 2 ] || fail "--worker-image requires an image name"
      worker_image="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "unknown argument: $1"
      ;;
  esac
done

[ -n "$worker_image" ] || {
  usage >&2
  fail "--worker-image is required; this script never silently builds or selects a Worker image"
}

cleanup() {
  original_status=$?
  trap - EXIT HUP INT TERM
  set +e
  cleanup_failed=0
  cleanup_container "$mysql_source_id" "$mysql_source"
  cleanup_container "$mysql_target_id" "$mysql_target"
  cleanup_container "$postgres_source_id" "$postgres_source"
  cleanup_container "$postgres_target_id" "$postgres_target"
  cleanup_container "$worker_container_id" "$worker_container"
  cleanup_network "$network_id" "$network_name"
  for container_name in "$mysql_source" "$mysql_target" "$postgres_source" "$postgres_target" "$worker_container"; do
    if [ -n "$container_name" ] && docker container inspect "$container_name" >/dev/null 2>&1; then
      printf '%s\n' "Runtime E2 cleanup left container: $container_name" >&2
      cleanup_failed=1
    fi
  done
  if [ -n "$network_name" ] && docker network inspect "$network_name" >/dev/null 2>&1; then
    printf '%s\n' "Runtime E2 cleanup left network: $network_name" >&2
    cleanup_failed=1
  fi
  if [ -n "$resource_prefix" ] && docker volume ls --filter "name=^${resource_prefix}" --format '{{.Name}}' | grep -q .; then
    printf '%s\n' "Runtime E2 unexpectedly created a named volume: $resource_prefix" >&2
    cleanup_failed=1
  fi
  if [ "$cleanup_failed" -ne 0 ]; then
    exit 1
  fi
  exit "$original_status"
}

cleanup_container() {
  container_id="$1"
  container_name="$2"
  [ -n "$container_id" ] || return 0
  if docker container inspect "$container_id" >/dev/null 2>&1; then
    label=$(docker container inspect \
      --format '{{index .Config.Labels "com.xiaoli.datax.runtime-e2"}}' \
      "$container_id" 2>/dev/null)
    if [ "$label" != "true" ]; then
      printf '%s\n' "Runtime E2 cleanup refused container with an unexpected label: $container_name" >&2
      cleanup_failed=1
      return 0
    fi
    if ! docker rm --force "$container_id" >/dev/null 2>&1 \
      && docker container inspect "$container_id" >/dev/null 2>&1; then
      printf '%s\n' "Runtime E2 cleanup could not remove container: $container_name" >&2
      cleanup_failed=1
    fi
  fi
}

cleanup_network() {
  current_network_id="$1"
  current_network_name="$2"
  [ -n "$current_network_id" ] || return 0
  if docker network inspect "$current_network_id" >/dev/null 2>&1; then
    label=$(docker network inspect \
      --format '{{index .Labels "com.xiaoli.datax.runtime-e2"}}' \
      "$current_network_id" 2>/dev/null)
    if [ "$label" != "true" ]; then
      printf '%s\n' "Runtime E2 cleanup refused network with an unexpected label: $current_network_name" >&2
      cleanup_failed=1
      return 0
    fi
    if ! docker network rm "$current_network_id" >/dev/null 2>&1 \
      && docker network inspect "$current_network_id" >/dev/null 2>&1; then
      printf '%s\n' "Runtime E2 cleanup could not remove network: $current_network_name" >&2
      cleanup_failed=1
    fi
  fi
}

require_immutable_docker_id() {
  resource_id="$1"
  resource_kind="$2"
  printf '%s' "$resource_id" | grep -Eq '^[0-9a-f]{64}$' \
    || fail "Runtime E2 $resource_kind did not return an immutable Docker ID"
}

command -v docker >/dev/null 2>&1 || fail "docker is required for Runtime E2"
command -v openssl >/dev/null 2>&1 || fail "openssl is required for ephemeral fixture credentials"
[ "$(docker version --format '{{.Server.Os}}' 2>/dev/null)" = "linux" ] \
  || fail "a running Linux Docker Engine is required for Runtime E2"
docker image inspect "$worker_image" >/dev/null 2>&1 \
  || fail "Worker image is unavailable: $worker_image"
[ -f "$runner_script" ] && [ ! -L "$runner_script" ] \
  || fail "Runtime E2 runner script is unavailable or unsafe"

run_entropy=$(openssl rand -hex 16)
[ "${#run_entropy}" -eq 32 ] || fail "Runtime E2 resource entropy generation failed"
run_suffix="$(date -u +%Y%m%d%H%M%S)-$$-$run_entropy"
resource_prefix="datax-runtime-e2-$run_suffix"
network_name="$resource_prefix-net"
mysql_source="$resource_prefix-mysql-source"
mysql_target="$resource_prefix-mysql-target"
postgres_source="$resource_prefix-postgres-source"
postgres_target="$resource_prefix-postgres-target"
worker_container="$resource_prefix-worker"

for resource_name in "$network_name" "$mysql_source" "$mysql_target" "$postgres_source" "$postgres_target" "$worker_container"; do
  if docker container inspect "$resource_name" >/dev/null 2>&1 \
    || docker network inspect "$resource_name" >/dev/null 2>&1 \
    || docker volume inspect "$resource_name" >/dev/null 2>&1; then
    fail "Runtime E2 resource name collision: $resource_name"
  fi
done

trap cleanup EXIT HUP INT TERM

fixture_password=$(openssl rand -hex 24)
mysql_root_password=$(openssl rand -hex 24)
[ "${#fixture_password}" -eq 48 ] || fail "fixture password generation failed"
[ "${#mysql_root_password}" -eq 48 ] || fail "root fixture password generation failed"

network_id=$(docker network create --internal \
  --label com.xiaoli.datax.runtime-e2=true \
  "$network_name")
require_immutable_docker_id "$network_id" "network"

start_mysql() {
  container_name="$1"
  docker run --detach --rm \
    --name "$container_name" \
    --network "$network_name" \
    --label com.xiaoli.datax.runtime-e2=true \
    --memory 768m \
    --pids-limit 256 \
    --tmpfs /var/lib/mysql:rw,noexec,nosuid,nodev,size=512m \
    --env MYSQL_DATABASE=audit \
    --env MYSQL_USER=datax \
    --env MYSQL_PASSWORD="$fixture_password" \
    --env MYSQL_ROOT_PASSWORD="$mysql_root_password" \
    "$mysql_image"
}

start_postgres() {
  container_name="$1"
  docker run --detach --rm \
    --name "$container_name" \
    --network "$network_name" \
    --label com.xiaoli.datax.runtime-e2=true \
    --memory 768m \
    --pids-limit 256 \
    --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m \
    --env POSTGRES_DB=audit \
    --env POSTGRES_USER=datax \
    --env POSTGRES_PASSWORD="$fixture_password" \
    "$postgres_image"
}

wait_mysql() {
  container_name="$1"
  attempt=0
  until docker exec --env "MYSQL_PWD=$fixture_password" "$container_name" \
    mysqladmin ping --silent -h 127.0.0.1 -udatax >/dev/null 2>&1
  do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 90 ] || fail "temporary MySQL did not become ready"
    sleep 1
  done
}

wait_postgres() {
  container_name="$1"
  attempt=0
  until docker exec "$container_name" \
    pg_isready --username=datax --dbname=audit >/dev/null 2>&1
  do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 90 ] || fail "temporary PostgreSQL did not become ready"
    sleep 1
  done
}

container_ip() {
  docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"
}

mysql_source_id=$(start_mysql "$mysql_source")
require_immutable_docker_id "$mysql_source_id" "MySQL source fixture"
mysql_target_id=$(start_mysql "$mysql_target")
require_immutable_docker_id "$mysql_target_id" "MySQL target fixture"
postgres_source_id=$(start_postgres "$postgres_source")
require_immutable_docker_id "$postgres_source_id" "PostgreSQL source fixture"
postgres_target_id=$(start_postgres "$postgres_target")
require_immutable_docker_id "$postgres_target_id" "PostgreSQL target fixture"
wait_mysql "$mysql_source"
wait_mysql "$mysql_target"
wait_postgres "$postgres_source"
wait_postgres "$postgres_target"

mysql_source_ip=$(container_ip "$mysql_source")
mysql_target_ip=$(container_ip "$mysql_target")
postgres_source_ip=$(container_ip "$postgres_source")
postgres_target_ip=$(container_ip "$postgres_target")
[ -n "$mysql_source_ip" ] && [ -n "$mysql_target_ip" ] \
  && [ -n "$postgres_source_ip" ] && [ -n "$postgres_target_ip" ] \
  || fail "temporary fixture containers have no isolated-network address"

worker_container_id=$(docker create \
  --name "$worker_container" \
  --network "$network_name" \
  --label com.xiaoli.datax.runtime-e2=true \
  --memory 1536m \
  --pids-limit 512 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=768m \
  --env DATAX_RUNTIME_E2_FIXTURE_PASSWORD="$fixture_password" \
  --env DATAX_RUNTIME_E2_TIMEOUT_SECONDS="$timeout_seconds" \
  --env DATAX_RUNTIME_E2_MYSQL_SOURCE_HOST="$mysql_source_ip" \
  --env DATAX_RUNTIME_E2_MYSQL_TARGET_HOST="$mysql_target_ip" \
  --env DATAX_RUNTIME_E2_POSTGRES_SOURCE_HOST="$postgres_source_ip" \
  --env DATAX_RUNTIME_E2_POSTGRES_TARGET_HOST="$postgres_target_ip" \
  --mount type=bind,src="$runner_script",dst=/tmp/datax_runtime_e2_runner.py,readonly \
  --workdir /tmp \
  --entrypoint python \
  "$worker_image" \
  /tmp/datax_runtime_e2_runner.py)
require_immutable_docker_id "$worker_container_id" "Worker fixture"
set +e
docker start --attach "$worker_container_id"
worker_start_status=$?
set -e
worker_exit_code=$(docker container inspect --format '{{.State.ExitCode}}' "$worker_container_id") \
  || fail "Runtime E2 Worker exit status is unavailable"
case "$worker_exit_code" in
  0) ;;
  *[!0-9]*|'') fail "Runtime E2 Worker exit status is invalid" ;;
  *) exit "$worker_exit_code" ;;
esac
[ "$worker_start_status" -eq 0 ] || exit "$worker_start_status"
