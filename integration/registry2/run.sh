#!/usr/bin/env bash
# Opt-in registry:2 harness. Clear-fails when Docker is unavailable.
# Starts an anonymous loopback-only registry:2 peer; tears down on exit.
# Usage: run.sh <path-to-registry2-harness-binary>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="${ROOT}/integration/registry2/docker-compose.yml"
PROJECT="zoci-registry2"
REGISTRY_HOST="127.0.0.1:5000"
IMAGE_REPO="zoci/smoke"
IMAGE_TAG="1.36.1"
SOURCE_IMAGE="busybox:${IMAGE_TAG}"
LOCAL_REF="${REGISTRY_HOST}/${IMAGE_REPO}:${IMAGE_TAG}"
MISSING_REF="${REGISTRY_HOST}/${IMAGE_REPO}:does-not-exist-zoci"

HARNESS="${1:?usage: run.sh <harness-binary>}"

if ! command -v docker >/dev/null 2>&1; then
  echo "integration-registry: Docker CLI not found. Install Docker or skip this opt-in step." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "integration-registry: Docker daemon not reachable. Start Docker or skip this opt-in step." >&2
  exit 1
fi

compose() {
  docker compose -f "${COMPOSE_FILE}" -p "${PROJECT}" "$@"
}

cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "integration-registry: starting registry:2 on ${REGISTRY_HOST}"
compose up -d

echo "integration-registry: waiting for GET /v2/"
ready=0
for _ in $(seq 1 60); do
  if curl -sf "http://${REGISTRY_HOST}/v2/" >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" -ne 1 ]]; then
  echo "integration-registry: registry did not become ready on http://${REGISTRY_HOST}/v2/" >&2
  compose logs >&2 || true
  exit 1
fi

echo "integration-registry: loading ${SOURCE_IMAGE} -> ${LOCAL_REF}"
docker pull "${SOURCE_IMAGE}"
docker tag "${SOURCE_IMAGE}" "${LOCAL_REF}"
docker push "${LOCAL_REF}"

echo "integration-registry: running harness"
"${HARNESS}" "${LOCAL_REF}" "${MISSING_REF}"

echo "integration-registry: ok"
