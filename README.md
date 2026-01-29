# Onetime Secrets Service

A small self-hostable service for sharing **one-time secrets** (a note can be viewed and then disappears).  
The backend is written in Go and uses **Valkey** as storage. An optional UI can be served by the same app.

## Features

- **One-time view**: Secrets are deleted after being viewed.
- **File attachments**: Securely share files alongside your text secrets.
- **Expiration**: Set a TTL for secrets.
- **Max views**: Configure how many times a secret can be viewed before deletion (default 1).
- **Passphrase protection**: Optional extra layer of security.
- **Client-side encryption**: The secret key is part of the URL fragment/path and not stored on the server (the server stores the encrypted payload).
- **Self-hostable**: Lightweight Go binary and Valkey storage.
- **HTMX-powered UI**: Minimal and fast user interface.

## Tech overview

- **Backend:** Go (`./cmd/server/main.go`)
- **Storage:** [Valkey](https://valkey.io/) (Redis-compatible)
- **Config:** environment variables (see below)
- **UI assets:** Tailwind CSS (via `@tailwindcss/cli`) and HTMX.
- **Runtime image:** distroless container (see `Dockerfile`)

## Configuration

The application is configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `OSS_PROD` | Set to `true` for production mode | `false` |
| `OSS_DOMAIN` | External domain of the service | `http://localhost:8080` |
| `OSS_DB` | Valkey/Redis address | `localhost:8081` |
| `OSS_HOST` | Address to bind the server to | `localhost:8080` |
| `OSS_UI` | Enable the web UI | `true` |
| `OSS_BASIC_AUTH_ENABLED` | Enable basic auth for the UI | `false` |
| `OSS_BASIC_AUTH_USERNAME`| Basic auth username | `admin` |
| `OSS_BASIC_AUTH_PASSWORD`| Basic auth password | `admin` |
| `OSS_CSRF_HASH_KEY` | Base64 encoded 32-byte key for CSRF (auto-generated if empty) | - |
| `OSS_CSRF_BLOCK_KEY` | Base64 encoded 32-byte key for CSRF (auto-generated if empty) | - |

## Quick start (development)

### 1) Start Valkey

Use the provided compose file to start a Valkey instance:

```bash
docker-compose up db
```

### 2) Run the application

```bash
go run ./cmd/server/main.go
```

The service will be available at `http://localhost:8080`.

## Building

### Docker

```bash
docker build -t onetime-secrets-service .
```

### Manual Build

```bash
go build -o oss ./cmd/server/main.go
```

## API

### Create a secret

`POST /api/v1/secret`

**Request Body:**
```json
{
  "value": "my secret message",
  "expiration": 3600,
  "max_views": 1,
  "password": "optional-password"
}
```

**Response:**
```json
{
  "url": "http://localhost:8080/key-uuid",
  "expires_at": "2026-01-29T18:14:00Z"
}
```

### Get a secret

`GET /api/v1/secret/{key-uuid}`

Returns the secret as `text/plain` and deletes it from the database (or decrements view count).

## License

MIT (See [LICENSE](LICENSE) file)
