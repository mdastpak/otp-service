# Docker Deployment Guide

## Overview

The OTP Service supports two deployment modes with scalable, secure Docker configurations:

- **Test** (Default): Development, debugging, and testing with comprehensive tools
- **Production**: Optimized, secure, and scalable deployment

## Quick Start

### Test Environment (Default)
```bash
# Start test environment
make start
# or
docker-compose up -d

# View logs
make logs

# Stop services
make stop
```

### Production Environment
```bash
# Build production image
make build-prod

# Deploy to production
make start-prod
# or
docker-compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

### Run Tests
```bash
# Run tests (in test environment)
make test
# or
docker-compose run --rm otp-service go test -v -race ./...
```

## Docker Configuration

### Multi-Stage Dockerfile

The `Dockerfile` supports two build targets:

- `production`: Optimized binary with UPX compression, minimal attack surface
- `test`: Debug-friendly with development tools and comprehensive testing capabilities

### Environment-Specific Compose Files

| Environment | Primary File | Override File | Description |
|-------------|--------------|---------------|-------------|
| Test (Default) | docker-compose.yml | docker-compose.override.yml | Auto-loaded for test/development |
| Production | docker-compose.yml | docker-compose.production.yml | Scalable production setup |

## Environment Configurations

### Test (.env.test) - Default Mode
- Debug logging enabled
- CORS permissive for local development
- Comprehensive logging for debugging
- Suitable for development, testing, and debugging
- Long OTP expiry times for easy testing
- Minimal resource limits

### Production (.env.production)
- Optimized for performance and security
- TLS/SSL enabled
- Strict CORS policies
- Comprehensive monitoring
- Resource limits enforced
- Short OTP expiry times for security

## Scalability Features

### Production Scaling
- **Load Balancing**: HAProxy with health checks and SSL termination
- **Service Replicas**: Configurable horizontal scaling
- **Resource Management**: CPU and memory limits/reservations
- **Rolling Deployments**: Zero-downtime updates

### Monitoring Stack
- **Prometheus**: Metrics collection and alerting
- **Grafana**: Visualization dashboards  
- **Redis Exporter**: Redis performance monitoring
- **HAProxy Stats**: Load balancer monitoring

### Security Features
- **Non-root containers**: All services run as non-privileged users
- **Read-only filesystems**: Prevents runtime tampering
- **Security scanning**: Automated vulnerability detection
- **Secrets management**: Secure credential handling
- **Network isolation**: Segmented container networks

## Advanced Usage

### Build Arguments
```bash
# Custom build with version
./scripts/build.sh -e production -v 1.0.0 --clean --security-scan

# Test build with tests (default)
./scripts/build.sh -e test --test
```

### Deployment Strategies
```bash
# Rolling deployment
./scripts/deploy.sh -e production -v 1.0.0 -s rolling

# Blue-green deployment  
./scripts/deploy.sh -e production -v 1.0.0 -s blue-green

# Rollback
./scripts/deploy.sh -e production --rollback
```

### Health Checks
```bash
# Application health
curl http://localhost:8080/health

# Metrics
curl http://localhost:9090/metrics

# HAProxy stats (production)
curl http://localhost:8404/stats
```

## Configuration Management

### Environment Variables
Key configurations can be customized via environment variables:

- `BUILD_VERSION`: Version tag for builds
- `BUILD_COMMIT`: Git commit hash
- `ENVIRONMENT`: Target environment (test|production)
- `DOCKER_REGISTRY`: Container registry URL
- `REDIS_HOST`: Redis hostname
- `SERVER_PORT`: Application port

### Volume Mounts
Production volumes for persistence:
- `redis-prod-data`: Redis data persistence
- `prometheus-data`: Metrics data
- `grafana-data`: Dashboard configurations
- Log directories for centralized logging

## Troubleshooting

### Common Issues

#### Redis Connection Failed
```bash
# Check Redis container
docker-compose ps redis

# Check Redis logs
docker-compose logs redis

# Test Redis connection
docker-compose exec redis redis-cli ping
```

#### Service Health Check Failed
```bash
# Check container logs
docker-compose logs otp-service

# Manual health check
curl -f http://localhost:8080/health

# Check container status
docker-compose ps
```

#### Build Failures
```bash
# Clean build
./scripts/build.sh -e development --clean

# Check build logs
docker-compose build --no-cache
```

### Performance Tuning

#### Memory Optimization
- Adjust Redis `maxmemory` settings
- Configure Go garbage collector (`GOGC`)
- Set appropriate container memory limits

#### Network Optimization  
- Use host networking for high-performance scenarios
- Configure connection pooling
- Optimize Redis pipeline usage

## Best Practices

### Test/Development
1. Use `docker-compose.override.yml` for local customizations
2. Mount source code volumes for hot reloading
3. Use test builds for debugging and development
4. Seed test data for consistent development

### Production
1. Always use versioned images (never `latest`)
2. Implement proper health checks
3. Configure resource limits
4. Use secrets management
5. Enable monitoring and alerting
6. Implement backup strategies
7. Test deployments in staging first

### Security
1. Run containers as non-root users
2. Use read-only filesystems where possible
3. Implement network segmentation
4. Regularly scan for vulnerabilities
5. Keep base images updated
6. Use minimal base images (Alpine, scratch)

## Monitoring and Alerting

### Prometheus Metrics
- Application performance metrics
- Redis connection and memory usage
- HTTP request/response metrics
- Custom business metrics

### Grafana Dashboards
- Service overview dashboard
- Redis performance dashboard  
- Application metrics dashboard
- Infrastructure monitoring

### Alert Rules
- Service availability alerts
- High error rate alerts
- Resource utilization alerts
- Custom business logic alerts

## Backup and Recovery

### Data Backup
```bash
# Redis data backup
docker-compose exec redis redis-cli BGSAVE
docker cp redis:/data/dump.rdb ./backup/

# Configuration backup
./scripts/deploy.sh --backup
```

### Disaster Recovery
1. Restore Redis data from backup
2. Redeploy services from version control
3. Update DNS/load balancer configurations
4. Verify service functionality

This configuration provides a robust, scalable foundation for deploying the OTP Service across different environments while maintaining security and operational best practices.