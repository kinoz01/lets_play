# Lets Play API

Spring Boot + MongoDB REST API that implements secure CRUD endpoints for users and products. It exposes JWT-based authentication, role-based authorization, validation, centralized error handling, CORS, and rate limiting so auditors can exercise the full checklist described in the subject.

## Prerequisites

- Java 17
- Maven 3.9+
- MongoDB (local or remote). Update `MONGODB_URI` if you aren't using the default `mongodb://localhost:27017/letsplay`.

## Configuration

Use environment variables (or set them in `application.properties`) when running the app:

| Variable | Default | Description |
| --- | --- | --- |
| `MONGODB_URI` | `mongodb://localhost:27017/letsplay` | Mongo connection string |
| `JWT_SECRET` | Base64 secret from `application.properties` | Base64-encoded HMAC key |
| `JWT_EXPIRATION` | `3600000` | Token lifetime (ms) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | `admin@letsplay.dev` / `Admin123!` | Seed admin credentials |
| `SERVER_SSL_ENABLED` | `false` | Set to `true` (plus keystore properties) to force HTTPS in production |

## Running & Testing

```bash
make run          # starts MongoDB via Docker Compose and boots the Spring app
make test         # runs the Maven test suite
make functional   # smoke-tests CRUD/auth flows (requires the API to be running)
make security     # static security checklist (hashing, CORS, rate limit, HTTPS toggle, etc.)
make stop         # stops the Spring app (Ctrl+C) and the MongoDB container
make fly-mongo    # provisions a dedicated MongoDB Fly app (volume + machine) and updates the API secret
```

`make run` expects a working Docker installation. If you already have MongoDB running elsewhere, skip the target and start the app manually with `MONGODB_URI=<your-uri> ./mvnw spring-boot:run`.

The seeded admin user (`ADMIN_EMAIL` / `ADMIN_PASSWORD`) can be used to manage users and products. Regular users register via `POST /api/auth/register` and authenticate via `POST /api/auth/login`.

## API Overview

- `POST /api/auth/register` *(public)*: register and receive a JWT.
- `POST /api/auth/login` *(public)*: obtain a JWT with email/password.
- `GET /api/auth/me`: returns the authenticated profile.
- `GET /api/products` *(public / @PermitAll)*: list all products.
- `GET /api/products/{id}` *(public)*, `POST /api/products`, `PUT /api/products/{id}`, `DELETE /api/products/{id}`: CRUD with owner/admin guard rails.
- `GET /api/users` *(admin)*, `GET /api/users/{id}` *(admin or owner via @PostAuthorize)*, `POST /api/users` *(admin)*, `PUT /api/users/{id}` *(admin or owner)*, `DELETE /api/users/{id}` *(admin)*.

All inputs are validated with Jakarta Bean Validation annotations. Passwords are hashed with BCrypt before being persisted. Controllers only return DTOs that omit sensitive fields.

## Security Measures

- JWT + Spring Security with `@EnableWebSecurity` and `@EnableMethodSecurity`.
- `@PreAuthorize`, `@PostAuthorize`, and `@PermitAll` guard every endpoint.
- BCrypt-hashed & salted passwords plus seeded admin account.
- Rate limiting (`RateLimitingFilter`) defends against brute force.
- CORS is restricted via `CorsConfigurationSource`.
- Validation rules on entities/DTOs mitigate Mongo injection attempts.
- Sensitive data (passwords) never leaves the server.
- HTTPS ready: set `SERVER_SSL_ENABLED=true` and provide keystore properties when deploying.

## Error Handling

`GlobalExceptionHandler` converts all exceptions (validation errors, missing resources, forbidden actions, etc.) into structured JSON payloads so the API never returns uncaught 5xx errors. Use `make functional` to verify the required scenarios end-to-end.

## Deploying on Fly.io

Fly now uses **two separate apps**:

- `lets-play-spring` (or whatever `fly.toml` declares) for the Spring Boot API
- `lets-play-spring-mongo` (default) for a dedicated MongoDB machine

1. `fly auth login` (if you aren't already authenticated) and make sure `fly.toml` describes the API app you intend to deploy.
2. Provision the Mongo app via the helper script:
   ```bash
   make fly-mongo
   # or with overrides
   FLY_MONGO_APP=my-db-app \
   FLY_MONGO_REGION=dfw \
   MONGO_VOLUME_SIZE=10 \
   FLY_ORG=my-org \
   make fly-mongo
   ```
   The script (`scripts/fly-mongo.sh`) will:
   - create the Mongo Fly app (unless it already exists) using `fly apps create`,
   - create/reuse the volume (`mongo_data` by default) in the requested region,
   - launch a `mongo:7` machine attached to that volume (default command `mongod --bind_ip_all --ipv6 ...` so it listens on Fly’s private network),
   - capture the Mongo app’s private Fly network IP, and
   - set `MONGODB_URI` as a secret on the API app so Spring talks to that private address.
   Tunable env vars include `FLY_API_APP`, `FLY_MONGO_APP`, `FLY_MONGO_REGION`, `MONGO_VOLUME_NAME`, `MONGO_VOLUME_SIZE`, `MONGO_MACHINE_NAME`, `MONGO_VM_SIZE`, `MONGO_DB_NAME`, `MONGO_PORT`, `MONGO_COMMAND`, and `MONGO_SECRET_NAME`. Set `MONGO_FORCE_RECREATE=true` if you want the script to destroy and recreate the Mongo machine (useful after changing command/size) and set `FLY_ORG` if your account spans multiple organizations.
3. Deploy (or redeploy) the API so it picks up the updated secret:
   ```bash
   fly deploy
   ```

The Mongo app only exposes a private IPv6 address inside Fly’s network, so nothing is reachable from the public internet. If you need authenticated Mongo, extend `scripts/fly-mongo.sh` to pass `MONGO_INITDB_ROOT_USERNAME` / `MONGO_INITDB_ROOT_PASSWORD` (or similar) to the `fly machines run` command, and update the URI formatting before rerunning `make fly-mongo`.
