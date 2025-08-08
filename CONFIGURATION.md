# Configuration Guide

The OTP service uses a **unified configuration approach** with environment variables as the primary source of truth.

## Configuration Hierarchy

1. **`.env`** - Local development defaults
2. **`.env.docker`** - Docker-specific overrides  
3. **`config.yaml`** - Fallback defaults and documentation
4. **Environment variables** - Ultimate override

## Files Overview

### 📄 `.env`

Default configuration for local development

```bash
cp .env.example .env
# Edit .env with your local settings
```

### 📄 `.env.docker`

Docker-specific configuration (used by docker-compose)

- Automatically sets `REDIS_HOST=redis`
- Sets `SERVER_HOST=0.0.0.0` for container networking

### 📄 `.env.example`

Template file showing all available configuration options

### 📄 `config.yaml`

- Provides fallback defaults
- Documents all configuration options
- Used when environment variables are not set

## Usage

### Local Development

```bash
# Copy template
cp .env.example .env

# Edit your settings
nano .env

# Run application
go run main.go
```

### Docker Development  

```bash
# Uses .env.docker automatically
docker-compose up

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
