#!/bin/sh
set -eu

test_container="datax-auth-postgres-test-$$"
test_password="$(openssl rand -hex 24)"

cleanup() {
  docker rm -f "$test_container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --detach \
  --name "$test_container" \
  --publish 127.0.0.1::5432 \
  --env POSTGRES_DB=datax_auth_test \
  --env POSTGRES_USER=datax_auth_test \
  --env POSTGRES_PASSWORD="$test_password" \
  postgres:15.18-alpine3.24@sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f >/dev/null

attempt=0
until docker exec "$test_container" \
  pg_isready -U datax_auth_test -d datax_auth_test >/dev/null 2>&1
do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "PostgreSQL 15 test container did not become ready" >&2
    exit 1
  fi
  sleep 1
done

host_port="$(
  docker port "$test_container" 5432/tcp |
    sed -n 's/^127\.0\.0\.1://p' |
    head -n 1
)"
if [ -z "$host_port" ]; then
  echo "Unable to resolve isolated PostgreSQL test port" >&2
  exit 1
fi

DATAX_AUTH_POSTGRES_TEST_URL="postgresql+psycopg://datax_auth_test:${test_password}@127.0.0.1:${host_port}/datax_auth_test" \
  .venv/bin/python -m pytest backend/tests/test_auth_postgres_concurrency.py
