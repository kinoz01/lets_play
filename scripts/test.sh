#!/usr/bin/env bash

######################################################################
# Configuration
######################################################################

# API URL
# local: http://localhost:8080
# local self signed: https://localhost:8443
# Deploy: https://lets-play-spring.fly.dev

BASE_URL="http://localhost:8080"

# curl base command (silent body, show errors, do not verify TLS)
CURL_CMD=(curl --insecure -sS)

# Admin credentials
ADMIN_EMAIL="admin@letsplay.dev"
ADMIN_PASSWORD="Admin123!"

# Regular user credentials for testing
USER_EMAIL="user1@example.com"
USER_PASSWORD="User123!"
# Secondary user for cross-ownership tests
SECOND_USER_EMAIL="user2@example.com"
SECOND_USER_PASSWORD="UserTwo123!"
# Emails for generating users via admin scenarios
MANAGED_USER_EMAIL="manageduser@example.com"
MANAGED_USER_PASSWORD="Managed123!"
SECOND_ADMIN_EMAIL="admin2@example.com"
SECOND_ADMIN_PASSWORD="AdminTwo123!"

# A bogus token to test invalid token behavior
BAD_TOKEN="this.is.not.a.valid.jwt.token"

######################################################################
# Colors & helpers
######################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
ORANGE='\033[38;5;208m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

text() {
	local txt="$1"
	local color="\033[38;5;208m" # orange-ish for titles
	printf "\n%b%s%b\n" "${color}" "${txt}" "${RESET}"
}

redtext() {
	local txt="$1"
	printf "%b%s%b\n" "${RED}" "${txt}" "${RESET}"
}

greentext() {
	local txt="$1"
	printf "%b%s%b\n" "${GREEN}" "${txt}" "${RESET}"
}

orangetext() {
	local txt="$1"
	printf "%b%s%b\n" "${ORANGE}" "${txt}" "${RESET}"
}

show_response() {
	if [[ ! -f response.json ]]; then
		return
	fi

	printf "%bResponse body:%b\n" "${YELLOW}" "${RESET}"

	if [[ ! -s response.json ]]; then
		printf "(empty)\n"
		return
	fi

	if command -v jq >/dev/null 2>&1; then
		if jq -e . response.json >/dev/null 2>&1; then
			jq . response.json
			return
		fi
	fi

	cat response.json
}

print_curl_command() {
	local filtered=("${CURL_CMD[@]}")
	local arg
	local skip_next=0

	for arg in "$@"; do
		if ((skip_next)); then
			skip_next=0
			continue
		fi
		if [[ "$arg" == "-o" ]]; then
			skip_next=1
			continue
		fi
		if [[ "$arg" == -o* ]]; then
			continue
		fi
		filtered+=("$arg")
	done

	local cmd=""
	for arg in "${filtered[@]}"; do
		printf -v cmd '%s%q ' "$cmd" "$arg"
	done

	cmd="${cmd% }"
	printf "%bCommand:%b %s\n" "${BLUE}" "${RESET}" "${cmd}" >&2
}

run_curl() {
	print_curl_command "$@"
	"${CURL_CMD[@]}" "$@"
}

# Wait for arrow key press
wait_for_key() {
	while true; do
		read -rsn 3 key </dev/tty
		if [[ "$key" == $'\e[C' ]] || [[ "$key" == $'\e[D' ]] || [[ "$key" == $'\e[B' ]]; then
			break
		fi
	done
}

# Colorize by HTTP status
colorize_pattern() {
	local headers status_line code color
	headers="$(cat)" # read everything from stdin (headers from curl -D -)

	status_line="$(printf '%s\n' "$headers" | grep -m1 -E '^HTTP/')"

	if [[ "$status_line" =~ ([0-9]{3}) ]]; then
		code="${BASH_REMATCH[1]}"
		if ((code >= 200 && code < 300)); then
			color="$GREEN"
		elif ((code >= 400 && code < 500)); then
			color="$ORANGE"
		elif ((code >= 500 && code < 600)); then
			color="$RED"
		else
			color="$RESET"
		fi
	else
		color="$RESET"
	fi

	# Print only the status line in color
	printf "%b%s%b\n" "$color" "$status_line" "$RESET"
}

# Generic runner that:
#  - prints test title
#  - executes curl, capturing headers and body
#  - colors status
#  - waits for key
run_test() {
	local title="$1"
	shift
	text "$title"

	# $@ are additional curl args (method, headers, path, data, etc.)
	# Headers go to colorize_pattern, body to response.json
	run_curl "$@" -D - -o response.json | colorize_pattern
	show_response

	# Optionally show a tiny preview of the body (first line) for debugging
	# echo "Body (first line):"
	# head -n 1 response.json

	wait_for_key
}

# Clean response.json at script exit
cleanup() {
	rm -f response.json
}
trap cleanup EXIT

######################################################################
# Auth helpers (require jq)
######################################################################

ADMIN_TOKEN=""
USER_TOKEN=""
USER_ID=""
ADMIN_ID=""
USER_CREATED_BY_ADMIN_ID=""
SECOND_ADMIN_ID=""
PRODUCT_ID=""
SECOND_USER_TOKEN=""
SECOND_ADMIN_TOKEN=""

login_admin() {
	text "Login as ADMIN to obtain token"

	run_curl -X POST "${BASE_URL}/api/auth/login" \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\"}" \
		-D - -o response.json | colorize_pattern
	show_response

	ADMIN_TOKEN="$(jq -r '.token // empty' response.json)"
	if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == "null" ]]; then
		redtext "Failed to extract ADMIN token (check AuthResponse JSON structure)."
	else
		greentext "ADMIN token acquired."
	fi

	wait_for_key
}

register_user() {
	text "Register normal USER (if already exists, this will return error)"

	run_curl -X POST "${BASE_URL}/api/auth/register" \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"${USER_EMAIL}\",\"password\":\"${USER_PASSWORD}\",\"name\":\"User One\"}" \
		-D - -o response.json | colorize_pattern
	show_response

	USER_TOKEN="$(jq -r '.token // empty' response.json)"

	if [[ -z "$USER_TOKEN" || "$USER_TOKEN" == "null" ]]; then
		orangetext "Could not extract user token from register (user may already exist, will try login)."
	else
		greentext "USER registered and token acquired from register."
	fi

	wait_for_key
}

login_user() {
	text "Login as USER to obtain token"

	run_curl -X POST "${BASE_URL}/api/auth/login" \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"${USER_EMAIL}\",\"password\":\"${USER_PASSWORD}\"}" \
		-D - -o response.json | colorize_pattern
	show_response

	if [[ -z "$USER_TOKEN" || "$USER_TOKEN" == "null" ]]; then
		USER_TOKEN="$(jq -r '.token // empty' response.json)"
	fi

	if [[ -z "$USER_TOKEN" || "$USER_TOKEN" == "null" ]]; then
		redtext "Failed to extract USER token (check AuthResponse JSON structure)."
	else
		greentext "USER token acquired."
	fi

	wait_for_key
}

register_second_user() {
	text "Register SECOND USER (cross-owner tests)"

	run_curl -X POST "${BASE_URL}/api/auth/register" \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"${SECOND_USER_EMAIL}\",\"password\":\"${SECOND_USER_PASSWORD}\",\"name\":\"User Two\"}" \
		-D - -o response.json | colorize_pattern
	show_response

	SECOND_USER_TOKEN="$(jq -r '.token // empty' response.json)"
	if [[ -z "$SECOND_USER_TOKEN" || "$SECOND_USER_TOKEN" == "null" ]]; then
		orangetext "Second user register did not return token (maybe already exists). Will try login."
	else
		greentext "Second user registered and token captured."
	fi

	wait_for_key
}

login_second_user() {
	text "Login as SECOND USER to obtain token"

	run_curl -X POST "${BASE_URL}/api/auth/login" \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"${SECOND_USER_EMAIL}\",\"password\":\"${SECOND_USER_PASSWORD}\"}" \
		-D - -o response.json | colorize_pattern
	show_response

	SECOND_USER_TOKEN="$(jq -r '.token // empty' response.json)"
	if [[ -z "$SECOND_USER_TOKEN" || "$SECOND_USER_TOKEN" == "null" ]]; then
		redtext "Failed to acquire SECOND USER token."
	else
		greentext "SECOND USER token acquired."
	fi

	wait_for_key
}

login_second_admin() {
	text "Login as SECOND ADMIN to obtain token"

	run_curl -X POST "${BASE_URL}/api/auth/login" \
		-H "Content-Type: application/json" \
		-d "{\"email\":\"${SECOND_ADMIN_EMAIL}\",\"password\":\"${SECOND_ADMIN_PASSWORD}\"}" \
		-D - -o response.json | colorize_pattern
	show_response

	SECOND_ADMIN_TOKEN="$(jq -r '.token // empty' response.json)"
	if [[ -z "$SECOND_ADMIN_TOKEN" || "$SECOND_ADMIN_TOKEN" == "null" ]]; then
		redtext "Failed to acquire SECOND ADMIN token."
	else
		greentext "SECOND ADMIN token acquired."
	fi

	wait_for_key
}

me_as_admin() {
	text "GET /api/auth/me as ADMIN"

	run_curl -X GET "${BASE_URL}/api/auth/me" \
		-H "Authorization: Bearer ${ADMIN_TOKEN}" \
		-D - -o response.json | colorize_pattern
	show_response

	ADMIN_ID="$(jq -r '.id // empty' response.json)"
	wait_for_key
}

me_as_user() {
	text "GET /api/auth/me as USER"

	run_curl -X GET "${BASE_URL}/api/auth/me" \
		-H "Authorization: Bearer ${USER_TOKEN}" \
		-D - -o response.json | colorize_pattern
	show_response

	USER_ID="$(jq -r '.id // empty' response.json)"
	wait_for_key
}

######################################################################
# Tests
######################################################################

text "=== AUTH ENDPOINT TESTS ==="

# 1. Health check (open endpoint)
run_test "Test 1 GET /actuator/health (open, no auth expected 200)" \
	-X GET "${BASE_URL}/actuator/health"

# 2. Register with missing fields
run_test "Test 2 POST /api/auth/register with missing body (400 / validation error)" \
	-X POST "${BASE_URL}/api/auth/register" \
	-H "Content-Type: application/json" \
	-d '{}'

# 3. Valid registration attempt
register_user

# 3b. Register a second regular user
register_second_user

# 4. Login with invalid credentials
run_test "Test 4 POST /api/auth/login with wrong password (401)" \
	-X POST "${BASE_URL}/api/auth/login" \
	-H "Content-Type: application/json" \
	-d "{\"email\":\"${USER_EMAIL}\",\"password\":\"WrongPassword123\"}"

# 5. Login with valid credentials
login_user

# 5b. Login with second user credentials
login_second_user

# 6. Login as admin
login_admin

# 7. /me without token
run_test "Test 7 GET /api/auth/me without token (403)" \
	-X GET "${BASE_URL}/api/auth/me"

# 8. /me with invalid token
run_test "Test 8 GET /api/auth/me with invalid token (should be 401/403)" \
	-X GET "${BASE_URL}/api/auth/me" \
	-H "Authorization: Bearer ${BAD_TOKEN}"

# 9. /me with valid USER token
me_as_user

# 10. /me with valid ADMIN token
me_as_admin

######################################################################
# PRODUCT ENDPOINT TESTS
######################################################################

text "=== PRODUCT ENDPOINT TESTS ==="

# Seed a few products so the first GET requests have data to return
declare -a SEED_PRODUCT_IDS=()
if [[ -n "$USER_TOKEN" && "$USER_TOKEN" != "null" ]]; then
	text "Pre-seed products via POST /api/products"
	declare -a SEED_PRODUCTS=(
		'{"name":"Seed Product One","description":"Seeded product","price":12.34}'
		'{"name":"Seed Product Two","description":"Another seeded product","price":23.45}'
	)
	for payload in "${SEED_PRODUCTS[@]}"; do
		run_curl -X POST "${BASE_URL}/api/products" \
			-H "Content-Type: application/json" \
			-H "Authorization: Bearer ${USER_TOKEN}" \
			-d "${payload}" \
			-D - -o response.json | colorize_pattern
		show_response

		seed_id="$(jq -r '.id // empty' response.json)"
		if [[ -n "$seed_id" && "$seed_id" != "null" ]]; then
			SEED_PRODUCT_IDS+=("$seed_id")
			greentext "Captured seeded product ID=${seed_id} for cleanup."
		else
			orangetext "Could not capture ID for seeded product payload."
		fi

		wait_for_key
	done
else
	orangetext "USER_TOKEN missing, skipping product pre-seed."
fi

# Public GET all products
run_test "Test 11 GET /api/products (public)" \
	-X GET "${BASE_URL}/api/products"

# Delete the seeded products to avoid polluting later tests
if [[ ${#SEED_PRODUCT_IDS[@]} -gt 0 ]]; then
	text "Cleanup seeded products via DELETE /api/products/{id}"
	for product_id in "${SEED_PRODUCT_IDS[@]}"; do
		run_curl -X DELETE "${BASE_URL}/api/products/${product_id}" \
			-H "Authorization: Bearer ${USER_TOKEN}" \
			-D - -o response.json | colorize_pattern
		show_response
		wait_for_key
	done
else
	orangetext "No seeded product IDs captured, skipping seeded product cleanup."
fi

# Public GET product by invalid id
run_test "Test 12 GET /api/products/{invalid} (public, expected 404)" \
	-X GET "${BASE_URL}/api/products/invalid-id-123"

# Create product without token
run_test "Test 13 POST /api/products without token (403)" \
	-X POST "${BASE_URL}/api/products" \
	-H "Content-Type: application/json" \
	-d '{"name":"P1","description":"No token","price":9.99}'

# Create product with invalid token
run_test "Test 14 POST /api/products with invalid token (401/403)" \
	-X POST "${BASE_URL}/api/products" \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer ${BAD_TOKEN}" \
	-d '{"name":"P2","description":"Bad token","price":19.99}'

# Create product as USER (authorized)
text "Test 15 POST /api/products as USER (should be 200)"
run_curl -X POST "${BASE_URL}/api/products" \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer ${USER_TOKEN}" \
	-d '{"name":"User Product","description":"Created by normal user","price":15.5}' \
	-D - -o response.json | colorize_pattern
show_response

PRODUCT_ID="$(jq -r '.id // empty' response.json)"
if [[ -n "$PRODUCT_ID" && "$PRODUCT_ID" != "null" ]]; then
	greentext "Captured PRODUCT_ID=${PRODUCT_ID} for later tests."
else
	orangetext "Could not capture PRODUCT_ID (check ProductResponse structure)."
fi
wait_for_key

# Get my products as USER
run_test "Test 16 GET /api/products/me as USER (authorized)" \
	-X GET "${BASE_URL}/api/products/me" \
	-H "Authorization: Bearer ${USER_TOKEN}"

# Get my products without token
run_test "Test 17 GET /api/products/me without token (403)" \
	-X GET "${BASE_URL}/api/products/me"

# Update product as USER (owner) [PUT]
if [[ -n "$PRODUCT_ID" && "$PRODUCT_ID" != "null" ]]; then
	run_test "Test 18 PUT /api/products/{id} as USER (owner, authorized)" \
		-X PUT "${BASE_URL}/api/products/${PRODUCT_ID}" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer ${USER_TOKEN}" \
		-d '{"name":"User Product Updated","description":"Updated by user","price":20.0}'
fi

# Partial update as USER (owner) [PATCH]
if [[ -n "$PRODUCT_ID" && "$PRODUCT_ID" != "null" ]]; then
	run_test "Test 19 PATCH /api/products/{id} as USER (owner, authorized)" \
		-X PATCH "${BASE_URL}/api/products/${PRODUCT_ID}" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer ${USER_TOKEN}" \
		-d '{"price":21.0}'
fi

# Patch product as ADMIN (should be allowed even if not owner)
if [[ -n "$PRODUCT_ID" && "$PRODUCT_ID" != "null" ]]; then
	run_test "Test 19.5 PATCH /api/products/{id} as ADMIN (allowed)" \
		-X PATCH "${BASE_URL}/api/products/${PRODUCT_ID}" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer ${ADMIN_TOKEN}" \
		-d '{"price":23}'
fi

# Delete product with second user's token (should be forbidden)
if [[ -n "$PRODUCT_ID" && "$PRODUCT_ID" != "null" && -n "$SECOND_USER_TOKEN" && "$SECOND_USER_TOKEN" != "null" ]]; then
	run_test "Test 19.6 DELETE /api/products/{id} as OTHER USER (forbidden)" \
		-X DELETE "${BASE_URL}/api/products/${PRODUCT_ID}" \
		-H "Authorization: Bearer ${SECOND_USER_TOKEN}"
fi

# Delete product without token
if [[ -n "$PRODUCT_ID" && "$PRODUCT_ID" != "null" ]]; then
	run_test "Test 20 DELETE /api/products/{id} without token (403)" \
		-X DELETE "${BASE_URL}/api/products/${PRODUCT_ID}"
fi

# Delete product with invalid token
if [[ -n "$PRODUCT_ID" && "$PRODUCT_ID" != "null" ]]; then
	run_test "Test 21 DELETE /api/products/{id} with invalid token (401/403)" \
		-X DELETE "${BASE_URL}/api/products/${PRODUCT_ID}" \
		-H "Authorization: Bearer ${BAD_TOKEN}"
fi

# Delete product as USER (owner)
if [[ -n "$PRODUCT_ID" && "$PRODUCT_ID" != "null" ]]; then
	run_test "Test 22 DELETE /api/products/{id} as USER (owner, authorized)" \
		-X DELETE "${BASE_URL}/api/products/${PRODUCT_ID}" \
		-H "Authorization: Bearer ${USER_TOKEN}"
fi

######################################################################
# USER ENDPOINT TESTS
######################################################################

text "=== USER ENDPOINT TESTS ==="

# GET /api/users without token
run_test "Test 23 GET /api/users without token (403)" \
	-X GET "${BASE_URL}/api/users"

# GET /api/users as USER (no admin role → 403)
run_test "Test 24 GET /api/users as normal USER (forbidden)" \
	-X GET "${BASE_URL}/api/users" \
	-H "Authorization: Bearer ${USER_TOKEN}"

# GET /api/users as ADMIN (allowed)
run_test "Test 25 GET /api/users as ADMIN (allowed)" \
	-X GET "${BASE_URL}/api/users" \
	-H "Authorization: Bearer ${ADMIN_TOKEN}"

# Create new user as ADMIN
text "Test 26 POST /api/users as ADMIN (create new user)"
run_curl -X POST "${BASE_URL}/api/users" \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer ${ADMIN_TOKEN}" \
	-d '{"email":"'${MANAGED_USER_EMAIL}'","password":"'${MANAGED_USER_PASSWORD}'","name":"Managed User","role":"USER"}' \
	-D - -o response.json | colorize_pattern
show_response

USER_CREATED_BY_ADMIN_ID="$(jq -r '.id // empty' response.json)"
if [[ -n "$USER_CREATED_BY_ADMIN_ID" && "$USER_CREATED_BY_ADMIN_ID" != "null" ]]; then
	greentext "Captured USER_CREATED_BY_ADMIN_ID=${USER_CREATED_BY_ADMIN_ID}"
else
	orangetext "Could not capture USER_CREATED_BY_ADMIN_ID (check UserResponse structure)."
fi
wait_for_key

# GET user by id as ADMIN
if [[ -n "$USER_CREATED_BY_ADMIN_ID" && "$USER_CREATED_BY_ADMIN_ID" != "null" ]]; then
	run_test "Test 27 GET /api/users/{id} as ADMIN (allowed)" \
		-X GET "${BASE_URL}/api/users/${USER_CREATED_BY_ADMIN_ID}" \
		-H "Authorization: Bearer ${ADMIN_TOKEN}"
fi

# GET user by id as USER (forbidden)
if [[ -n "$USER_CREATED_BY_ADMIN_ID" && "$USER_CREATED_BY_ADMIN_ID" != "null" ]]; then
	run_test "Test 28 GET /api/users/{id} as USER (403)" \
		-X GET "${BASE_URL}/api/users/${USER_CREATED_BY_ADMIN_ID}" \
		-H "Authorization: Bearer ${USER_TOKEN}"
fi

# Attempt to delete self as USER (sforbidden)
if [[ -n "$USER_ID" && "$USER_ID" != "null" ]]; then
	run_test "Test 28.5 DELETE /api/users/{id} as USER (forbidden)" \
		-X DELETE "${BASE_URL}/api/users/${USER_ID}" \
		-H "Authorization: Bearer ${USER_TOKEN}"
fi

# Update self as USER (PUT /api/users/{USER_ID})
if [[ -n "$USER_ID" && "$USER_ID" != "null" ]]; then
	run_test "Test 29 PUT /api/users/{id} as USER (forbidden)" \
		-X PUT "${BASE_URL}/api/users/${USER_ID}" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer ${USER_TOKEN}" \
		-d '{"name":"User One Updated"}'
fi

# Update other user as USER (should be forbidden)
if [[ -n "$USER_CREATED_BY_ADMIN_ID" && "$USER_CREATED_BY_ADMIN_ID" != "null" ]]; then
	run_test "Test 30 PUT /api/users/{id} as USER (forbidden)" \
		-X PUT "${BASE_URL}/api/users/${USER_CREATED_BY_ADMIN_ID}" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer ${USER_TOKEN}" \
		-d '{"name":"Hacked Name"}'
fi

# Partial update (PATCH) self as USER
if [[ -n "$USER_ID" && "$USER_ID" != "null" ]]; then
	run_test "Test 31 PATCH /api/users/{id} as USER (forbidden)" \
		-X PATCH "${BASE_URL}/api/users/${USER_ID}" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer ${USER_TOKEN}" \
		-d '{"name":"User One Partially Updated"}'
fi

# Delete user as ADMIN
if [[ -n "$USER_CREATED_BY_ADMIN_ID" && "$USER_CREATED_BY_ADMIN_ID" != "null" ]]; then
	run_test "Test 32 DELETE /api/users/{id} as ADMIN (allowed, 204)" \
		-X DELETE "${BASE_URL}/api/users/${USER_CREATED_BY_ADMIN_ID}" \
		-H "Authorization: Bearer ${ADMIN_TOKEN}"
fi

# Create secondary admin for CRUD checks
text "Test 32.1 POST /api/users as ADMIN (create second admin)"
run_curl -X POST "${BASE_URL}/api/users" \
	-H "Content-Type: application/json" \
	-H "Authorization: Bearer ${ADMIN_TOKEN}" \
	-d '{"email":"'${SECOND_ADMIN_EMAIL}'","password":"'${SECOND_ADMIN_PASSWORD}'","name":"Second Admin","role":"ADMIN"}' \
	-D - -o response.json | colorize_pattern
show_response

SECOND_ADMIN_ID="$(jq -r '.id // empty' response.json)"
if [[ -n "$SECOND_ADMIN_ID" && "$SECOND_ADMIN_ID" != "null" ]]; then
	greentext "Captured SECOND_ADMIN_ID=${SECOND_ADMIN_ID}"
else
	orangetext "Could not capture SECOND_ADMIN_ID (check UserResponse structure)."
fi
wait_for_key

if [[ -n "$SECOND_ADMIN_ID" && "$SECOND_ADMIN_ID" != "null" ]]; then
	login_second_admin

	run_test "Test 32.2 PATCH /api/users/{id} as ADMIN (update admin)" \
		-X PATCH "${BASE_URL}/api/users/${SECOND_ADMIN_ID}" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer ${ADMIN_TOKEN}" \
		-d '{"name":"Second Admin Patched"}'
fi

# Delete admin as USER (forbidden)
if [[ -n "$ADMIN_ID" && "$ADMIN_ID" != "null" ]]; then
	run_test "Test 33 DELETE /api/users/{adminId} as USER (forbidden)" \
		-X DELETE "${BASE_URL}/api/users/${ADMIN_ID}" \
		-H "Authorization: Bearer ${USER_TOKEN}"
fi

######################################################################
# Error tests
######################################################################

text "=== OTHER ERROR TESTS ==="

# Unknown endpoint
run_test "Test 34 GET /unknown (should be 404)" \
	-X GET "${BASE_URL}/unknown"

# Wrong method on /api/auth/login (GET instead of POST)
run_test "Test 35 GET /api/auth/login (Method Not Allowed 405 or 404)" \
	-X GET "${BASE_URL}/api/auth/login"

text "All tests executed. response.json has been removed at exit."
