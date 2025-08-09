# Configuration Guide

The OTP service uses a **unified configuration approach** with environment variables as the primary source of truth.

## Configuration Hierarchy

1. **`.env.test`** - Default test/development mode (default)
2. **`.env.production`** - Production environment configuration
3. **`config.yaml`** - Fallback defaults and documentation
4. **Environment variables** - Ultimate override

## Files Overview

### 📄 `.env.test`

Default configuration for test/development mode. This is the **default** environment file used by:
- Local development
- Docker Compose (test mode)
- CI/CD testing
- Development debugging

### 📄 `.env.production`

Production environment configuration used for:
- Production deployments
- Docker Compose production mode (`docker-compose -f docker-compose.yml -f docker-compose.production.yml up`)
- High-performance production settings

### 📄 `config.yaml`

- Provides fallback defaults
- Documents all configuration options
- Used when environment variables are not set

## Usage

### Local Development

```bash
# Run with test configuration (default)
go run main.go

# Or with custom environment variables
OTP_LENGTH=8 OTP_EXPIRY=120s go run main.go
```

### Docker Development  

```bash
# Uses .env.test by default
docker-compose up

# For production mode
docker-compose -f docker-compose.yml -f docker-compose.production.yml up

# With monitoring
docker-compose --profile monitoring up
```

### Production

Set environment variables directly or use your deployment platform's configuration system.

## Configuration Options

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `REDIS_HOST` | Redis server hostname | `localhost` |
| `REDIS_PORT` | Redis server port | `6379` |
| `REDIS_PASSWORD` | Redis password | `` |
| `REDIS_INDICES` | Redis database indices | `0-5` |
| `REDIS_KEY_PREFIX` | Key prefix for Redis | `` |
| `REDIS_TIMEOUT` | Redis operation timeout | `5` |
| `SERVER_HOST` | Server bind address | `localhost` |
| `SERVER_PORT` | Server port | `8080` |
| `SERVER_MODE` | Server mode (release/test) | `test` |
| `SERVER_TIMEOUT_READ` | HTTP read timeout | `5` |
| `SERVER_TIMEOUT_WRITE` | HTTP write timeout | `10` |
| `SERVER_TIMEOUT_IDLE` | HTTP idle timeout | `120` |
| `SERVER_TIMEOUT_READ_HEADER` | HTTP read header timeout | `2` |
| `TLS_ENABLED` | Enable TLS | `false` |
| `TLS_CERT_FILE` | TLS certificate file | `cert.pem` |
| `TLS_KEY_FILE` | TLS private key file | `key.pem` |
| `TLS_CLIENT_CERTS` | TLS client certificates | `client_certs.pem` |
| `HASH_KEYS` | Enable Redis key hashing | `true` |
| **OTP Configuration** | | |
| `OTP_LENGTH` | OTP code length | `6` |
| `OTP_EXPIRY` | OTP expiration time | `60s` |
| `OTP_MAX_ATTEMPTS` | Maximum verification attempts | `10` |
| `OTP_CLEANUP_INTERVAL` | Cleanup worker interval | `30s` |
| **CORS Configuration** | | |
| `CORS_ALLOWED_ORIGINS` | Allowed origins (* or comma-separated) | `*` |
| `CORS_ALLOWED_METHODS` | Allowed HTTP methods | `GET,POST,OPTIONS` |
| `CORS_ALLOWED_HEADERS` | Allowed headers | `Content-Type,Authorization` |
| `CORS_EXPOSED_HEADERS` | Exposed headers | `Content-Length` |
| `CORS_MAX_AGE` | Preflight cache duration (seconds) | `3600` |
| `CORS_ALLOW_CREDENTIALS` | Allow credentials | `true` |
| **Security Configuration** | | |
| `SECURITY_HEADERS_ENABLED` | Enable security headers | `false` |
| `HSTS_MAX_AGE` | HSTS max age (seconds, 0=disabled) | `0` |
| `CSP_POLICY` | Content Security Policy | `` |

## Migration from Old Setup

The previous setup used:

- Inline environment variables in docker-compose
- Separate config files
- Hardcoded values

**New unified approach benefits:**

- ✅ Single source of truth (`.env`)
- ✅ Environment-specific overrides
- ✅ Better documentation
- ✅ Easier deployment
- ✅ Consistent development/production parity
