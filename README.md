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
