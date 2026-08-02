#!/bin/sh
#
# Run a disposable real-PostgreSQL E2 subset. This deliberately does not
# start the product Compose stack, DataX, or MySQL, and it must never be
# reported as E3/E4 evidence.

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
python="$repository_root/.venv/bin/python"
alembic="$repository_root/.venv/bin/alembic"
postgres_image="postgres:15.18-alpine3.24@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f"
container_name="datax-e2-postgres-$$"
temporary_directory=""

cleanup() {
  if [ -n "$container_name" ]; then
    docker rm --force "$container_name" >/dev/null 2>&1 || true
  fi
  if [ -n "$temporary_directory" ] && [ -d "$temporary_directory" ]; then
    rm -rf -- "$temporary_directory"
  fi
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

write_hex_secret() {
  target="$1"
  umask 077
  openssl rand -hex 32 | tr -d '\n' > "$target"
  chmod 600 "$target"
  [ "$(wc -c < "$target" | tr -d ' ')" = "64" ] || fail "secret generation failed"
}

command -v docker >/dev/null 2>&1 || fail "docker is required for this E2 subset"
command -v openssl >/dev/null 2>&1 || fail "openssl is required for temporary secrets"
[ -x "$python" ] || fail ".venv/bin/python is required"
[ -x "$alembic" ] || fail ".venv/bin/alembic is required"
[ "$(docker version --format '{{.Server.Os}}' 2>/dev/null)" = "linux" ] \
  || fail "a running Linux Docker Engine is required"

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/datax-e2-postgres.XXXXXX")
chmod 700 "$temporary_directory"
owner_secret="$temporary_directory/migration-owner-password"
guard_secret="$temporary_directory/egress-guard-password"
api_secret="$temporary_directory/api-password"
worker_secret="$temporary_directory/worker-password"
write_hex_secret "$owner_secret"
write_hex_secret "$guard_secret"
write_hex_secret "$api_secret"
write_hex_secret "$worker_secret"

owner_password=$(cat "$owner_secret")
guard_password=$(cat "$guard_secret")
api_password=$(cat "$api_secret")
worker_password=$(cat "$worker_secret")

docker run --detach --rm \
  --name "$container_name" \
  --label com.xiaoli.datax.e2-temporary=true \
  --publish 127.0.0.1::5432 \
  --memory 512m \
  --pids-limit 128 \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=384m \
  --env POSTGRES_DB=datax_e2_test \
  --env POSTGRES_USER=datax_migration_test \
  --env POSTGRES_PASSWORD="$owner_password" \
  "$postgres_image" >/dev/null

attempt=0
until docker exec "$container_name" \
  pg_isready -U datax_migration_test -d datax_e2_test >/dev/null 2>&1
do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 45 ] || fail "temporary PostgreSQL did not become ready"
  sleep 1
done

host_port=$(docker port "$container_name" 5432/tcp | sed -n 's/^127\.0\.0\.1://p' | head -n 1)
[ -n "$host_port" ] || fail "temporary PostgreSQL has no loopback port"

owner_url="postgresql+psycopg://datax_migration_test:${owner_password}@127.0.0.1:${host_port}/datax_e2_test"
api_url="postgresql+psycopg://datax_api:${api_password}@127.0.0.1:${host_port}/datax_e2_test"
worker_url="postgresql+psycopg://datax_worker:${worker_password}@127.0.0.1:${host_port}/datax_e2_test"
guard_url="postgresql+psycopg://datax_egress_guard:${guard_password}@127.0.0.1:${host_port}/datax_e2_test"

run_alembic() {
(
  cd "$repository_root/backend"
  DES_DATABASE_HOST=127.0.0.1 \
  DES_DATABASE_PORT="$host_port" \
  DES_DATABASE_NAME=datax_e2_test \
  DES_DATABASE_USER=datax_migration_test \
  DES_DATABASE_PASSWORD_FILE="$owner_secret" \
  DES_EGRESS_GUARD_DATABASE_PASSWORD_FILE="$guard_secret" \
  DES_API_DATABASE_PASSWORD_FILE="$api_secret" \
  DES_WORKER_DATABASE_PASSWORD_FILE="$worker_secret" \
  "$alembic" -c alembic.ini "$@"
)
}

run_alembic upgrade head
# Prove the new watermark table can be removed and recreated on real
# PostgreSQL, then retain the prior Worker-session rollback coverage too.
run_alembic downgrade 20260802_0017
run_alembic upgrade head
run_alembic downgrade 20260802_0016
run_alembic upgrade head

cd "$repository_root"
DATAX_MIGRATION_POSTGRES_TEST_URL="$owner_url" \
DATAX_API_POSTGRES_TEST_URL="$api_url" \
DATAX_WORKER_POSTGRES_TEST_URL="$worker_url" \
DATAX_EGRESS_GUARD_POSTGRES_TEST_URL="$guard_url" \
DATAX_CREDENTIAL_POSTGRES_TEST_URL="$owner_url" \
DATAX_AUTH_POSTGRES_TEST_URL="$owner_url" \
PYTHONDONTWRITEBYTECODE=1 \
  "$python" -m pytest -q -p no:cacheprovider \
    backend/tests/test_runtime_database_roles_postgres.py \
    backend/tests/test_egress_guard_postgres.py \
    backend/tests/test_audit_append_only_postgres.py \
    backend/tests/test_audit_readiness_postgres.py \
    backend/tests/test_credentials_postgres.py \
    backend/tests/test_auth_postgres_concurrency.py

printf '%s\n' \
  'POSTGRES_E2_SUBSET_PASSED: real disposable PostgreSQL migrations, role boundaries, audit append-only/readiness replay, credential concurrency, and auth concurrency passed. This is E2 subset evidence only; it is not DataX E3, Windows E4, or product-Compose acceptance.'
