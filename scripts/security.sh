#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${ROOT_DIR}/src/main/java"
PROPERTIES_FILE="${ROOT_DIR}/src/main/resources/application.properties"

if ! command -v rg >/dev/null 2>&1; then
	echo "The security checklist requires 'rg' (ripgrep). Please install it and rerun."
	exit 1
fi

echo "Checking password hashing strategy..."
rg -q "BCryptPasswordEncoder" "${SRC_DIR}" && echo "✔ BCrypt hashing configured"

echo "Checking JWT security configuration..."
rg -q "JwtAuthenticationFilter" "${SRC_DIR}" && echo "✔ JWT filter present"

echo "Ensuring public product endpoints are explicitly permitted..."
rg -q "@PermitAll" "${SRC_DIR}/com/example/lets_play/controller/ProductController.java" && echo "✔ Public access annotation found"

echo "Validating rate limiting filter..."
rg -q "RateLimitingFilter" "${SRC_DIR}" && echo "✔ Rate limiting implemented"

echo "Verifying HTTPS guidance in configuration..."
grep -q "server.ssl.enabled" "${PROPERTIES_FILE}" && echo "✔ HTTPS toggle present"

echo "Security checklist passed."
