#!/usr/bin/env bash
# Chaos test that stops Postgres during traffic and checks the service recovers.
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
CLIENT_ID="${CLIENT_ID:?must be set}"
CLIENT_SECRET="${CLIENT_SECRET:?must be set}"
LOGIN_USERNAME="${LOGIN_USERNAME:?must be set}"
LOGIN_PASSWORD="${LOGIN_PASSWORD:?must be set}"

OUTAGE_SECONDS="${OUTAGE_SECONDS:-45}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-3}"
RECOVERY_TIMEOUT_SECONDS="${RECOVERY_TIMEOUT_SECONDS:-60}"
MAX_ACCEPTABLE_LATENCY_SECONDS="${MAX_ACCEPTABLE_LATENCY_SECONDS:-32}"

AUTH_HEADER="Authorization: Basic $(printf '%s' "${CLIENT_ID}:${CLIENT_SECRET}" | base64)"
LOGIN_URL="${BASE_URL}/api/v1/auth/login"
LOGIN_BODY="{\"username\":\"${LOGIN_USERNAME}\",\"password\":\"${LOGIN_PASSWORD}\"}"

unexpected_status_count=0
hang_count=0

call_login() {
    curl -s -o /dev/null -w '%{http_code} %{time_total}' \
        -X POST "${LOGIN_URL}" \
        -H "Content-Type: application/json" \
        -H "${AUTH_HEADER}" \
        -d "${LOGIN_BODY}"
}

echo "== Chaos test: Postgres outage against ${BASE_URL} =="

echo "-- Warm-up: confirming baseline 200s before the outage --"
for _ in 1 2 3; do
    read -r status latency <<< "$(call_login)"
    echo "  status=${status} latency=${latency}s"
    if [[ "${status}" != "200" ]]; then
        echo "ABORT: baseline request did not return 200 - fix connectivity before running the chaos test."
        exit 1
    fi
done

echo "-- Stopping Postgres (docker compose stop postgres) --"
docker compose stop postgres

echo "-- Polling during the outage window (${OUTAGE_SECONDS}s, every ${POLL_INTERVAL_SECONDS}s) --"
outage_end=$(( $(date +%s) + OUTAGE_SECONDS ))
while (( $(date +%s) < outage_end )); do
    read -r status latency <<< "$(call_login)"
    flag=""
    if [[ "${status}" != "503" ]]; then
        flag=" <-- UNEXPECTED (wanted 503)"
        unexpected_status_count=$((unexpected_status_count + 1))
    fi
    if awk -v a="${latency}" -v b="${MAX_ACCEPTABLE_LATENCY_SECONDS}" 'BEGIN { exit !(a > b) }'; then
        flag="${flag} <-- HUNG (latency exceeded ${MAX_ACCEPTABLE_LATENCY_SECONDS}s)"
        hang_count=$((hang_count + 1))
    fi
    echo "  status=${status} latency=${latency}s${flag}"
    sleep "${POLL_INTERVAL_SECONDS}"
done

echo "-- Restarting Postgres (docker compose start postgres) --"
docker compose start postgres

echo "-- Polling for recovery (up to ${RECOVERY_TIMEOUT_SECONDS}s) --"
recovered=false
recovery_deadline=$(( $(date +%s) + RECOVERY_TIMEOUT_SECONDS ))
while (( $(date +%s) < recovery_deadline )); do
    read -r status latency <<< "$(call_login)"
    echo "  status=${status} latency=${latency}s"
    if [[ "${status}" == "200" ]]; then
        recovered=true
        break
    fi
    sleep "${POLL_INTERVAL_SECONDS}"
done

echo
echo "== Result =="
echo "Unexpected (non-503) responses during outage: ${unexpected_status_count}"
echo "Hung requests (> ${MAX_ACCEPTABLE_LATENCY_SECONDS}s) during outage: ${hang_count}"
echo "Recovered to 200 after Postgres restart: ${recovered}"

if [[ "${unexpected_status_count}" -eq 0 && "${hang_count}" -eq 0 && "${recovered}" == "true" ]]; then
    echo "PASS: app degraded to 503s during the outage and recovered cleanly."
    exit 0
else
    echo "FAIL: see flagged lines above."
    exit 1
fi
