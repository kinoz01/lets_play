HTTPS_PROPS=src/main/resources/application.properties
KEYSTORE_FILE=keystore.p12
KEYSTORE_PASS?=changeit
KEY_ALIAS?=letsplay-local
HTTPS_PORT?=8443
SECRETS_FILE?=.env.local

help:
	@echo "Available targets:"
	@echo "  make run         - load .env.local, starts MongoDB (via Docker) and the Spring API"
	@echo "  make test        - run test scripts executing different API calls (use right arrow to go to next call)"
	@echo "  make https       - create a self-signed SSL certificate and enable HTTPS in application.properties"
	@echo "  make secrets     - generate .env.local with JWT secret and admin credentials"
	@echo "  make build       - compiles and packages the project"
	@echo "  make stop        - stops the Spring Boot app and dockerized MongoDB"
	@echo "  make fly-mongo   - provisions a dedicated Mongo Fly app + secret"

run: mongo-up
	@set -a; \
	if [ -f ".env.local" ]; then \
		echo "Loading environment variables from .env.local"; \
		. ./.env.local; \
	else \
		echo "No .env.local found; proceeding with existing environment, to generate automatically u might use the make secrets target"; \
	fi; \
	set +a; \
	./mvnw spring-boot:run 

stop: mongo-down

build:
	./mvnw clean package

fly-mongo:
	./scripts/fly-mongo.sh

test:
	./scripts/test.sh

secrets:
	@set -e; \
	JWT_VALUE="$${JWT_SECRET_VALUE:-$$(openssl rand -base64 48)}"; \
	ADMIN_EMAIL_VALUE="$${ADMIN_EMAIL_VALUE:-admin@letsplay.dev}"; \
	ADMIN_PASSWORD_VALUE="$${ADMIN_PASSWORD_VALUE:-Admin123!}"; \
	echo "Writing secrets to $(SECRETS_FILE)"; \
	{ \
		echo "JWT_SECRET=$$JWT_VALUE"; \
		echo "ADMIN_EMAIL=$$ADMIN_EMAIL_VALUE"; \
		echo "ADMIN_PASSWORD=$$ADMIN_PASSWORD_VALUE"; \
	} > $(SECRETS_FILE); \
	echo "Secrets saved. Load them with: \"set -a; . ./.env.local; set +a\" or use \"make run\" to load automatically."

https:
	@set -e; \
	if [ ! -f "$(KEYSTORE_FILE)" ]; then \
		echo "Generating PKCS12 keystore $(KEYSTORE_FILE)..."; \
		keytool -genkeypair \
			-alias $(KEY_ALIAS) \
			-keyalg RSA \
			-keysize 2048 \
			-storetype PKCS12 \
			-keystore $(KEYSTORE_FILE) \
			-validity 365 \
			-storepass $(KEYSTORE_PASS) \
			-dname "CN=localhost, OU=LetsPlay, O=LetsPlay, L=Local, S=Local, C=US"; \
	else \
		echo "$(KEYSTORE_FILE) already exists; skipping keytool."; \
	fi; \
	if ! grep -q "server\.ssl\.key-store=$(KEYSTORE_FILE)" "$(HTTPS_PROPS)"; then \
		echo "Appending HTTPS configuration to $(HTTPS_PROPS)..."; \
		printf "\n# Local HTTPS configuration\n" >> "$(HTTPS_PROPS)"; \
		printf "server.port=%s\n" "$(HTTPS_PORT)" >> "$(HTTPS_PROPS)"; \
		printf "server.ssl.enabled=true\n" >> "$(HTTPS_PROPS)"; \
		printf "server.ssl.key-store=%s\n" "$(KEYSTORE_FILE)" >> "$(HTTPS_PROPS)"; \
		printf "server.ssl.key-store-password=%s\n" "$(KEYSTORE_PASS)" >> "$(HTTPS_PROPS)"; \
		printf "server.ssl.key-store-type=PKCS12\n" >> "$(HTTPS_PROPS)"; \
		printf "server.ssl.key-alias=%s\n" "$(KEY_ALIAS)" >> "$(HTTPS_PROPS)"; \
	else \
		echo "HTTPS configuration already present in $(HTTPS_PROPS)."; \
	fi

mongo-up:
	@$(MAKE) _mongo-up

mongo-down:
	@$(MAKE) _mongo-down

_mongo-up:
	@set -e; \
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
		COMPOSE_CMD="docker compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		COMPOSE_CMD="docker-compose"; \
	else \
		echo "Docker Compose is required to start MongoDB automatically (install Docker Desktop or docker-compose)."; \
		exit 1; \
	fi; \
	if command -v docker >/dev/null 2>&1; then \
		CONTAINER_NAME="lets-play-mongo"; \
		if docker ps -a --format '{{.Names}}' | grep -Fxq "$$CONTAINER_NAME"; then \
			echo "Removing stale MongoDB container $$CONTAINER_NAME ..."; \
			docker rm -f "$$CONTAINER_NAME" >/dev/null 2>&1 || true; \
		fi; \
	fi; \
	echo "Starting MongoDB container using $$COMPOSE_CMD ..."; \
	$$COMPOSE_CMD up -d mongo; \
	echo "MongoDB container is ready."

_mongo-down:
	@set -e; \
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
		COMPOSE_CMD="docker compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		COMPOSE_CMD="docker-compose"; \
	else \
		exit 0; \
	fi; \
	echo "Stopping MongoDB container..."; \
	$$COMPOSE_CMD down >/dev/null 2>&1 || true; \
	echo "MongoDB container stopped."
