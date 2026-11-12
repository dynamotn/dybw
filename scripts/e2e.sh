#!/usr/bin/env bash
# @file e2e.sh
# @brief Build the e2e image, start a throwaway Vaultwarden and run the end-to-end tests in Docker.
# @description Docker settings come from the environment (DOCKER_HOST, DOCKER_CONFIG).
#   Vaultwarden is recreated every run: a third run on one container hits HTTP 429.
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -t dybw-e2e -f tests/e2e/Dockerfile .
docker rm -f dybw-bw-it > /dev/null 2>&1 || true
docker run -d --rm --name dybw-bw-it -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false \
  -e DISABLE_ICON_DOWNLOAD=true -e LOGIN_RATELIMIT_MAX_BURST=1000 \
  -e LOGIN_RATELIMIT_SECONDS=1 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  vaultwarden/server:1.37.4@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055 > /dev/null
trap 'docker rm -f dybw-bw-it > /dev/null 2>&1 || true' EXIT
# Wait until Vaultwarden answers, from inside its own network namespace.
for _ in $(seq 60); do
  docker run --rm --network container:dybw-bw-it dybw-e2e python3 -c \
    'import urllib.request as u; u.urlopen("http://127.0.0.1:80/alive")' 2> /dev/null && break
  sleep 2
done
docker run --rm --network container:dybw-bw-it -e BW_E2E_URL=http://127.0.0.1:80 \
  -v "$PWD":/src -v dybw-target:/target -v dybw-cargo:/usr/local/cargo/registry dybw-e2e
