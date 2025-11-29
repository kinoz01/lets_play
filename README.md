# Lets Play API

Lets Play API is a basic Spring Boot + MongoDB CRUD API that use JWT authentication, request throttling, method-level authorization, and centralized error handling. The service can be run locally or accessed through the hosted instance at **https://lets-play-spring.fly.dev**.

## Overview

- **Security**: Stateless JWT authentication, rate limiting via a custom filter, and `@EnableMethodSecurity` guards on controllers.
- **Data layer**: MongoDB collections for users and products, with seeded admin credentials to bootstrap access.
- **Tooling**: Makefile targets orchestrate local development workflows, generate HTTPS keystores, and provision supporting infrastructure on Fly.io. An interactive curl script (`scripts/test.sh`) exercises the API end to end.

## Prerequisites

- Java 17 or newer
- Maven 3.9+
- docker or docker-compose (for MongoDB container)
- Docker Daemon running

## Local Setup

Before running locally, set the required environment variables (manually or via `make secrets` followed by sourcing `.env.local`):

- `JWT_SECRET` – Base64-encoded signing key (e.g., `openssl rand -base64 48`)
- `ADMIN_EMAIL` – Seed administrator email address
- `ADMIN_PASSWORD` – Seed administrator password

Then:

1. Build the project: `./mvnw clean package`
2. Start MongoDB and the API: `make run`
3. Verify readiness: `curl http://localhost:8080/actuator/health`

### HTTPS locally

Run `make https` to:

1. Generate `keystore.p12`
2. Append SSL settings to `src/main/resources/application.properties`
3. Serve the API on `https://localhost:8443`

If you rely on Postman or similar tools, don't forget to import the generated certificate via settings. Example for Thunder Client:

```json
"thunder-client.certificates": [
  {
    "name": "LetsPlay Keystore",
    "pfxPath": "${workspaceFolder}/keystore.p12",
    "passphrase": "your-keystore-password",
    "hosts": [
      "https://localhost:8443"
    ]
  }
]
```

## API Summary

### Authentication

- `POST /api/auth/register` – Create a user and receive a JWT in the response.
- `POST /api/auth/login` – Exchange email & password for a JWT.
- `GET /api/auth/me` – Retrieve the authenticated profile information (email, name, etc...).

### Products

- `GET /api/products` and `GET /api/products/{id}` – Public read access.
- `POST /api/products` – Requires a valid token; the new product is tied to the caller.
- `PUT`/`PATCH /api/products/{id}` – Owners can modify their products; admins can modify any product.
- `DELETE /api/products/{id}` – Owners and admins can remove products.
- `GET /api/products/me` – List products owned by the caller.

### Users

- `GET /api/users` – Admin only.
- `GET /api/users/{id}` – Admin or self.
- `POST /api/users` – Admin can create additional users.
- `PUT`/`PATCH /api/users/{id}` – Admin only; self-updates are disabled.
- `DELETE /api/users/{id}` – Admin only can delete users.

## Request payload examples

Below are sample JSON bodies for endpoints that require input data. Adjust values as needed.

### Authentication

`POST /api/auth/register` (public)

```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "password": "Password123!"
}
```

`POST /api/auth/login` (public)

```json
{
  "email": "jane@example.com",
  "password": "Password123!"
}
```

### Products

`POST /api/products` *(bearer token from user or admin)*

Example header: `Authorization: Bearer {{user_token}}`

```json
{
  "name": "Acoustic Guitar",
  "description": "Solid spruce top with mahogany back.",
  "price": 299.99,
  "stock": 5
}
```

`PUT /api/products/{id}` *(bearer token from owner or admin)*

Example header: `Authorization: Bearer {{user_token}}`

```json
{
  "name": "Acoustic Guitar Pro",
  "description": "Upgraded tuners and hardshell case.",
  "price": 349.99,
  "stock": 7
}
```

`PATCH /api/products/{id}` *(bearer token from owner or admin)*

Example header: `Authorization: Bearer {{admin_token}}`

```json
{
  "price": 279.99,
  "stock": 10
}
```

### Users (admin-only)

`POST /api/users` *(bearer token from admin)*

Example header: `Authorization: Bearer {{admin_token}}`

```json
{
  "name": "Managed User",
  "email": "managed@example.com",
  "password": "Managed123!",
  "role": "USER"
}
```

`PUT /api/users/{id}` *(bearer token from admin)*

Example header: `Authorization: Bearer {{admin_token}}`

```json
{
  "name": "Managed User Updated",
  "email": "managed.updated@example.com",
  "role": "ADMIN"
}
```

`PATCH /api/users/{id}` *(bearer token from admin)*

Example header: `Authorization: Bearer {{admin_token}}`

```json
{
 "name": "Managed User Patched",
 "password": "NewPassword!1"
}
```

## Make Targets

| Target | Purpose |
| --- | --- |
| `make run` | Launch MongoDB (docker-compose) and run the API via `spring-boot:run`. |
| `make stop` | Stop the Mongo container. |
| `make build` | Run the Maven build. |
| `make test` | Execute the interactive curl test suite (`scripts/test.sh`). |
| `make fly-mongo` | Provision a MongoDB machine on Fly.io and update secrets for the API app. |
| `make secrets` | Generate `.env.local` with `JWT_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` values (uses `openssl rand` for the JWT secret). |
| `make https` | Generate a PKCS12 keystore and append SSL configuration. |
| `make help` | Display a summary of available targets. |

Variables such as `KEYSTORE_PASS`, `FLY_MONGO_REGION`, or `MONGO_VOLUME_SIZE` can be overridden per invocation, e.g., `KEYSTORE_PASS=my-pass make https`.

After running `make secrets`, load the environment variables with:

```bash
set -a; . ./.env.local; set +a
```

This exports `JWT_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` so Spring picks them up via `app.jwt.secret`, `app.admin.email`, and `app.admin.password`.

## Testing Workflow

`scripts/test.sh` issues a curated sequence of curl requests, writes responses to `response.json`, colorizes status lines, and prints each command so it can be re-run manually. The script pauses between tests, allowing time to inspect the results or copy commands into another terminal.

## Deployment

- Production URL: **https://lets-play-spring.fly.dev**
- `make fly-mongo` provisions a companion MongoDB app (default: `lets-play-spring-mongo`) on Fly.io and stores the resulting `MONGODB_URI` as a secret on the API app.
- Deployments are performed with `fly deploy`. Before deploying, set secrets on Fly with:

  ```bash
  fly secrets set \
    JWT_SECRET="your-generated-secret" \
    ADMIN_EMAIL="admin@letsplay.dev" \
    ADMIN_PASSWORD="Admin123!"
  ```

## Additional Notes

- Controllers expose DTOs only; passwords never appear in responses.
- Rate limiting returns structured `ApiError` responses consistent with the rest of the API.
- `GlobalExceptionHandler` produces uniform JSON for validation errors, access violations, and missing resources.

## References

- [Apache Maven Guides](https://maven.apache.org/guides/index.html)
- [Spring Boot Maven Plugin](https://docs.spring.io/spring-boot/3.5.7/maven-plugin)
- [Spring Web Reference](https://docs.spring.io/spring-boot/3.5.7/reference/web/servlet.html)
- [Spring Security Reference](https://docs.spring.io/spring-boot/3.5.7/reference/web/spring-security.html)
- [Spring Data MongoDB](https://docs.spring.io/spring-boot/3.5.7/reference/data/nosql.html#data.nosql.mongodb)
- [Spring Boot Actuator](https://docs.spring.io/spring-boot/3.5.7/reference/actuator/index.html)
- [Spring Guides](https://spring.io/guides/) (REST, MVC, Security, MongoDB, Actuator)
