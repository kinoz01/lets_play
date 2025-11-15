#!/usr/bin/env bash
set -euo pipefail

if ! command -v curl >/dev/null 2>&1; then
	echo "'curl' is required for functional tests."
	exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
	echo "'python3' is required for JSON parsing in functional tests."
	exit 1
fi

BASE_URL=${API_BASE_URL:-http://localhost:8080}
ADMIN_EMAIL=${ADMIN_EMAIL:-admin@letsplay.dev}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-Admin123!}

api_request() {
	local method="$1"
	local endpoint="$2"
	local payload="${3:-}"
	local token="${4:-}"

	local tmp
	tmp=$(mktemp)

	local headers=(-H "Content-Type: application/json")
	if [[ -n "${token}" ]]; then
		headers+=(-H "Authorization: Bearer ${token}")
	fi

	local data_args=()
	if [[ -n "${payload}" ]]; then
		data_args=(-d "${payload}")
	fi

	local http_code
	http_code=$(curl -s -o "${tmp}" -w "%{http_code}" -X "${method}" "${headers[@]}" "${data_args[@]}" "${BASE_URL}${endpoint}")

	if [[ "${http_code}" != 2* ]]; then
		echo "Request ${method} ${endpoint} failed with status ${http_code}"
		cat "${tmp}"
		rm -f "${tmp}"
		exit 1
	fi

	cat "${tmp}"
	rm -f "${tmp}"
}

extract_json_field() {
	python3 - "$1" <<'PY'
import json
import sys
payload = json.load(sys.stdin)
field = sys.argv[1]
value = payload
for part in field.split('.'):
	value = value[part]
print(value)
PY
}

echo "Checking API health at ${BASE_URL}/actuator/health"
HEALTH_RESPONSE=$(curl -s -o /tmp/health.json -w "%{http_code}" "${BASE_URL}/actuator/health")
if [[ "${HEALTH_RESPONSE}" != 2* ]]; then
	echo "Health check failed with status ${HEALTH_RESPONSE}"
	cat /tmp/health.json
	rm -f /tmp/health.json
	exit 1
fi
grep -q '"status":"UP"' /tmp/health.json || { echo "Unexpected health payload:"; cat /tmp/health.json; rm -f /tmp/health.json; exit 1; }
rm -f /tmp/health.json

echo "Authenticating as admin ${ADMIN_EMAIL}"
ADMIN_RESPONSE=$(api_request "POST" "/api/auth/login" "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}")
ADMIN_TOKEN=$(echo "${ADMIN_RESPONSE}" | extract_json_field token)

UNIQUE=$(date +%s)
NEW_USER_EMAIL="functional+${UNIQUE}@test.dev"
echo "Creating functional test user ${NEW_USER_EMAIL}"
USER_RESPONSE=$(api_request "POST" "/api/users" "{\"name\":\"Functional User\",\"email\":\"${NEW_USER_EMAIL}\",\"password\":\"Secret123!\",\"role\":\"USER\"}" "${ADMIN_TOKEN}")
USER_ID=$(echo "${USER_RESPONSE}" | extract_json_field id)

NEW_PLAYER_EMAIL="player+${UNIQUE}@test.dev"
echo "Registering public user ${NEW_PLAYER_EMAIL}"
REGISTER_RESPONSE=$(api_request "POST" "/api/auth/register" "{\"name\":\"Player\",\"email\":\"${NEW_PLAYER_EMAIL}\",\"password\":\"Secret123!\"}")
PLAYER_TOKEN=$(echo "${REGISTER_RESPONSE}" | extract_json_field token)

echo "Creating product as ${NEW_PLAYER_EMAIL}"
PRODUCT_RESPONSE=$(api_request "POST" "/api/products" "{\"name\":\"Controller\",\"description\":\"Wireless game controller\",\"price\":49.99}" "${PLAYER_TOKEN}")
PRODUCT_ID=$(echo "${PRODUCT_RESPONSE}" | extract_json_field id)

echo "Validating public access to GET /api/products"
api_request "GET" "/api/products"

echo "Attempting to update a missing product (expecting graceful 404)"
set +e
STATUS=$(curl -s -o /tmp/functional-error.json -w "%{http_code}" -X PUT -H "Authorization: Bearer ${PLAYER_TOKEN}" -H "Content-Type: application/json" -d "{\"name\":\"Controller\",\"description\":\"Wireless game controller\",\"price\":59.99}" "${BASE_URL}/api/products/${PRODUCT_ID}missing")
EXIT_CODE=$?
set -e
if [[ ${EXIT_CODE} -ne 0 ]]; then
	echo "Curl exited with ${EXIT_CODE}, please ensure the API is running."
	exit ${EXIT_CODE}
fi
if [[ "${STATUS}" != "404" ]]; then
	echo "Expected 404 response, got ${STATUS}"
	cat /tmp/functional-error.json
	exit 1
fi
rm -f /tmp/functional-error.json

echo "Functional smoke tests completed successfully."
