.PHONY: help run build test functional security mongo-up mongo-down stop

help:
	@echo "Available targets:"
	@echo "  make run         - starts MongoDB (via Docker) and the API"
	@echo "  make build       - compiles and packages the project"
	@echo "  make test        - runs the Maven test suite"
	@echo "  make functional  - executes scripted functional smoke tests (server must be running)"
	@echo "  make security    - runs the static security checklist"
	@echo "  make stop        - stops the Spring Boot app (CTRL+C) and dockerized MongoDB"

run: mongo-up
	./mvnw spring-boot:run

build:
	./mvnw clean package

test:
	./mvnw test

functional:
	./scripts/functional.sh

security:
	./scripts/security.sh

mongo-up:
	@$(MAKE) _mongo-up

mongo-down:
	@$(MAKE) _mongo-down

stop: mongo-down

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
