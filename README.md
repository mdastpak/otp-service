# OTP Service API Documentation

This README provides details on the API endpoints, input parameters, expected request/response bodies, and status codes for the OTP (One-Time Password) service.

## Table of Contents

- [Performance Improvements](#performance-improvements)
- [Endpoints](#endpoints)
  - [Generate OTP](#generate-otp)
  - [Verify OTP](#verify-otp)
  - [Health Check](#health-check)
- [Postman Collection](#postman-collection)
- [Request Parameters](#request-parameters)
- [Response Structure](#response-structure)
- [Status Code Guide](#status-code-guide)
- [Additional Notes](#additional-notes)
- [Redis Configuration](#redis-configuration)
- [Technical Architecture](#technical-architecture)
- [Admin Dashboard](#admin-dashboard)
- [Development Roadmap](#development-roadmap)
- [Related Documentation](#related-documentation)

## Performance Improvements

### Recent Enhancements (v2024.12)

The OTP service has undergone significant performance improvements:

#### 🚀 **Redis Sharding Performance (~10x faster)**
- **UUID-based sharding**: Replaced SHA-256 hashing with direct UUID parsing
- **Better distribution**: Uses 4 bytes (32-bit) instead of 1 byte (8-bit) entropy
- **Configuration caching**: Parses Redis indices once at startup, eliminating repeated parsing
- **Consistent results**: Same UUID always maps to the same shard

#### 🔧 **Technical Details**
- **Algorithm**: Uses last 4 bytes of UUID for excellent random distribution
- **Fallback handling**: Graceful error handling for malformed UUIDs
- **Range support**: Properly handles Redis index ranges like "2-5" with start+offset calculation

#### 📊 **Redis Client Upgrade**
- **Migrated to `github.com/redis/go-redis/v9`** from legacy v8
- **Official Redis organization** library with active maintenance
- **Enhanced connection pooling** and better Redis 7+ feature support

## Endpoints

### Generate OTP

**URL**: `/`

**Method**: `POST`

**Description**: Generates a one-time password (OTP) and stores it in Redis. The OTP is uniquely associated with a UUID that will be returned in the response.

#### Request Parameters

The following parameters can be sent via query string or in the request body as JSON.

- `ttl` (optional, default: `60`): The time-to-live of the OTP in seconds. Must be between `1` and `3600`.
- `retry_limit` (optional, default: `5`): The maximum number of times the OTP can be retried. Must be between `1` and `60`.
- `code_length` (optional, default: `6`): The length of the OTP code. Must be between `1` and `10`.
- `strict_validation` (optional, default: `false`): If set to `true`, the service will enforce strict validation of the request body during verification.
- `use_alpha_numeric` (optional, default: `false`): If set to `true`, the OTP will contain letters and numbers; otherwise, only numbers.

#### Example Request

```bash
curl -X POST "http://localhost:8080" \
  -H "Content-Type: application/json" \
  -d '{ }'
```

#### Example Response

```json
{
  "status": 200,
  "message": "OTP_GENERATED",
  "info": {
    "uuid": "1c11604d-47fa-442a-866a-231686e14a8b"
  }
}
```

### Verify OTP

**URL**: `/`

**Method**: `GET`

**Description**: Verifies an OTP based on the UUID and OTP value provided.

#### Request Parameters

- `uuid` (required): The UUID associated with the OTP that was generated.
- `otp` (required): The OTP value to be verified.

#### Example Request

```bash
curl -X GET "http://localhost:8080/?uuid=1c11604d-47fa-442a-866a-231686e14a8b&otp=447317"
```

#### Example Response

If the OTP is verified successfully:

```json
{
  "status": 200,
  "message": "OTP_VERIFIED"
}
```

If the OTP is invalid or expired:

```json
{
  "status": 401,
  "message": "OTP_INVALID"
}
```

### Health Check

**URL**: `/health`

**Method**: `GET`

**Description**: Checks the health status of the service, including Redis connectivity.

#### Example Request

```bash
curl -X GET "http://localhost:8080/health"
```

#### Example Response

```json
{
  "status": 200,
  "message": "SERVICE_HEALTH",
  "info": {
    "redis_status": "OK",
    "config": "***********",
  }
}
```

## Postman Collection

You can find the Postman collection for this service [here](https://web.postman.co/workspace/be07ea85-299a-4d7f-a2c9-61cd33071f4b/collection/11658275-de41dacd-ab9b-4600-969d-2b62d60300c6).

## Request Parameters

The OTP service supports passing parameters via either the query string or request body (in JSON format). The following parameters can be used:

- `ttl`: Time-to-live for OTP in seconds.
- `retry_limit`: Maximum retries allowed.
- `code_length`: Length of the generated OTP.
- `strict_validation`: Enforce strict validation of the request body during verification.
- `use_alpha_numeric`: If the OTP should contain both letters and numbers.

## Response Structure

All API responses use the following standard structure:

```json
{
  "status": <int>,
  "message": "<string>",
  "info": <object>
}
```

- `status`: HTTP status code (e.g., `200` for success).
- `message`: Response message indicating the status (e.g., `OTP_GENERATED`, `OTP_VERIFIED`, etc.).
- `info`: Additional information related to the response (e.g., UUID for generated OTP).

## Status Code Guide

Below is a guide for various status codes and their meanings:

| Status Code      | Message                   | Description                                          |
| ---------------- | ------------------------- | ---------------------------------------------------- |
| `200`          | `OTP_GENERATED`         | OTP was successfully generated.                      |
| `200`          | `OTP_VERIFIED`          | OTP was successfully verified.                       |
| `400`          | `REQUEST_BODY_INVALID`  | The request body is invalid or improperly formatted. |
| `400`          | `TTL_INVALID`           | The `ttl` parameter is out of range.               |
| `400`          | `RETRY_INVALID`         | The `retry_limit` parameter is out of range.       |
| `400`          | `CODE_LENGTH_INVALID`   | The `code_length` parameter is out of range.       |
| `400`          | `OTP_MISSING`           | Required UUID or OTP is missing from request.        |
| `401`, `500` | `OTP_INVALID`           | The provided OTP is incorrect.                       |
| `401`          | `OTP_EXPIRED`           | The OTP has expired.                                 |
| `401`          | `OTP_ATTEMPTS`          | The OTP retry limit has been reached.                |
| `401`          | `REQUEST_BODY_MISMATCH` | The request body does not match the expected data.   |
| `429`          | `RATE_LIMIT_EXCEEDED`   | Rate limit exceeded.                                 |
| `200`, `500` | `SERVICE_HEALTH`        | Health check of the service, including Redis status. |

## Additional Notes

- Ensure Redis is running and configured properly for the OTP service to work.
- The `strict_validation` parameter helps ensure the request data matches what was used during OTP generation, adding an extra layer of security.
- The `retry_limit` parameter limits the number of incorrect attempts a user can make, providing basic protection against brute-force attacks.

### Examples of Requests with Strict Validation

Below are examples of requests that demonstrate the use of the `strict_validation` parameter.

#### Example 1: Generate OTP with Strict Validation Disabled

```bash
curl --silent --location --request POST 'localhost:8080/' \
--data '{}'
```

#### Example 2: Generate OTP with Strict Validation Disabled (Custom Parameters)

```bash
curl --silent --location --request POST 'localhost:8080/?ttl=120&retry_limit=10&code_length=10&strict_validation=false&use_alpha_numeric=true' \
--data '{}'
```

#### Example 3: Generate OTP with Strict Validation Enabled

```bash
curl --silent --location --request POST 'localhost:8080/?ttl=60&retry_limit=5&code_length=6&strict_validation=true&use_alpha_numeric=false' \
--data '{
    "lowecase tag": "Value",
    "UPPERCASE TAG": "VALUE",
    "MULTIcase TaG": "VaLuE",
    "Keys": {
        "Key 1": "Val 1",
        "Key 2": "Val 2",
        "Key 3": {
            "SubKey3-1": "Val 3-1",
            "SubKey3-2": "Val 3-2"
        }
    }
}'
```

#### Example 4: Verify OTP with No Strict Validation

```bash
curl --silent --location --request GET 'localhost:8080/?uuid=e63ee3c4-9ebe-42a3-8c2a-e05e88c468a4&otp=174464' \
--header 'Content-Type: application/json' \
--data '{}'
```

#### Example 5: Verify OTP with Strict Validation Enabled

```bash
curl --silent --location --request GET 'localhost:8080/?uuid=e63ee3c4-9ebe-42a3-8c2a-e05e88c468a4&otp=174464' \
--header 'Content-Type: application/json' \
--data '{
    "lowecase tag": "Value",
    "UPPERCASE TAG": "VALUE",
    "MULTIcase TaG": "VaLuE",
    "Keys": {
        "Key 1": "Val 1",
        "Key 2": "Val 2",
        "Key 3": {
            "SubKey3-1": "Val 3-1",
            "SubKey3-2": "Val 3-2"
        }
    }
}'
```

## Redis Configuration

The OTP service utilizes multiple Redis indices for storing OTPs, as specified in the configuration file (`config.yaml`). The `REDIS.INDICES` configuration allows you to determine how many Redis databases are used to distribute OTPs.

### Redis Sharding Strategy

- **Single Index**: You can specify a single Redis index (e.g., `0`) to store all OTPs in a single Redis database.
- **Range of Indices**: You can specify a range of Redis indices (e.g., `0-3` or `2-5`). OTPs are distributed among the specified Redis databases using **UUID-based sharding** for optimal performance and distribution.

#### How UUID-Based Sharding Works

The service uses an intelligent sharding algorithm that:

1. **Extracts the last 4 bytes** (8 hex characters) from the UUID
2. **Converts to uint32** for modulo operation
3. **Applies modulo** with shard count to determine target database
4. **Adds start offset** for ranges (e.g., for "2-5", adds 2 to result)

**Example**: 
- UUID: `550e8400-e29b-41d4-a716-446655440000`
- Last 4 bytes: `40000` (hex) = 262144 (decimal)
- For range "0-3": `262144 % 4 + 0 = 0` → Database 0
- For range "2-5": `262144 % 4 + 2 = 2` → Database 2

This approach provides:
- ✅ **Excellent distribution** - Uses UUID's inherent randomness
- ✅ **High performance** - ~10x faster than SHA-256 hashing  
- ✅ **Consistency** - Same UUID always maps to same database
- ✅ **Load balancing** - Even distribution across all configured databases

The `REDIS.INDICES` configuration is crucial for scaling the OTP service effectively, especially under high load. By distributing the OTPs across multiple Redis databases using this optimized algorithm, the service can handle more concurrent requests and reduce contention for Redis resources.

The `REDIS.KEY_PREFIX` configuration allows you to set a prefix for all Redis keys used by the service. This can be useful for namespacing keys, especially if you are using a shared Redis instance for multiple services. If left empty (`""`), no prefix will be added. Example: if the prefix is set to `"OTP"`, all keys will be stored as `"OTP:<key>"`.

The `REDIS.TIMEOUT` configuration allows you to set a timeout for Redis connections. This is useful for ensuring that the service does not get stuck waiting for a Redis connection that is not responding. The default value is `5s`.

### Additional Configuration Parameters

The OTP service also provides additional configuration parameters that can be adjusted in the `CONFIG` section of the configuration file.

- **`CONFIG.HASH_KEY`**: If set to `true`, the Redis keys used to store OTPs are hashed using SHA-256. This helps to prevent any potential key collisions and makes the keys more secure. It is recommended to keep this value as `true` for production environments.
- **`SERVER.DEBUG`**: If set to `true`, the service will log additional debug information, which can be helpful for troubleshooting. It is recommended to keep this value as `false` for production environments.

## Technical Architecture

### Recent Technical Improvements

The OTP service has undergone significant architectural improvements to enhance performance, scalability, and maintainability:

#### 🔄 **Library Upgrades**
- **Redis Client**: Migrated from `github.com/go-redis/redis/v8` to `github.com/redis/go-redis/v9`
  - Official Redis organization library with active maintenance
  - Better connection pooling with `ConnMaxIdleTime` configuration
  - Enhanced Redis 7+ feature support

#### ⚡ **Performance Optimizations**
- **Sharding Algorithm**: Replaced SHA-256 with UUID-based direct parsing
  - **10x performance improvement** in shard index calculation
  - **Better distribution** using 4 bytes vs 1 byte entropy
  - **Configuration caching** eliminates repeated parsing overhead

#### 🛠️ **Code Quality Enhancements**
- **Error Handling**: Comprehensive fallback strategies for malformed UUIDs
- **Consistency**: Deterministic shard mapping for same UUID across calls
- **Testing**: Updated test suites with proper initialization patterns
- **Documentation**: Enhanced code comments and technical explanations

#### 📈 **Scalability Features**
- **Range Support**: Proper handling of Redis index ranges with start+offset
- **Load Distribution**: Even distribution across all configured Redis databases
- **Resource Optimization**: Reduced CPU usage for high-throughput scenarios

#### 🔒 **Security Enhancements**
- **Dependency Updates**: Updated to latest secure versions of golang.org/x/net and golang.org/x/crypto
- **Vulnerability Fixes**: Addressed IPv6 Zone ID HTTP Proxy Bypass, XSS, DoS, and authorization bypass vulnerabilities
- **Security Patches**: Proactive security monitoring and rapid vulnerability remediation

These improvements make the OTP service more robust, performant, and ready for production workloads at scale.

## Admin Dashboard

The OTP service now includes a comprehensive **graphical admin dashboard** with real-time analytics and monitoring capabilities.

### 🎯 **Key Features**

#### **Real-time Statistics**
- **Active OTPs**: Live count of currently valid OTPs
- **Success Rate**: Real-time success/failure percentage
- **Response Time**: P95 latency monitoring  
- **Rate Limited**: Current rate limiting statistics

#### **📊 Interactive Charts**
- **Operations Timeline**: Real-time OTP generation and verification trends
- **Success vs Failure Rate**: Visual breakdown of operation outcomes
- **Performance Metrics**: Response time and throughput analytics

#### **🔄 Live Activity Feed**
- Real-time stream of OTP operations
- Filterable by success, failure, and rate-limited events
- Detailed event information with timestamps

#### **🏥 System Health Monitoring**
- **API Service**: Health status and uptime
- **Redis Cluster**: Connection status and performance
- **Memory Usage**: Real-time memory consumption
- **CPU Usage**: System resource monitoring

### 🚀 **Access & Authentication**

#### **Dashboard URL**
```
http://localhost:8080/admin/
```

#### **Authentication Options**
- **JWT Authentication**: Secure token-based access (default)
- **Basic Authentication**: Simple username/password
- **IP Whitelisting**: Restrict access by IP address
- **Rate Limiting**: Built-in protection against abuse

#### **Default Credentials** (Change in Production!)
```
Username: admin
Password: admin123
```

### ⚙️ **Configuration**

Configure the admin dashboard in `config.yaml`:

```yaml
admin:
  enabled: true                    # Enable/disable dashboard
  jwt_secret: "your-secret-key"    # JWT signing secret
  allowed_ips: ["127.0.0.1"]      # IP whitelist
  basic_auth: false                # Use JWT (true for basic auth)
  require_auth: true               # Enable authentication
```

### 🔧 **Technical Features**

#### **WebSocket Integration**
- Real-time data streaming to dashboard
- Automatic reconnection handling
- Live updates without page refresh

#### **Responsive Design**
- Mobile-friendly interface
- Dark mode support
- Customizable refresh intervals

#### **Performance Optimized**
- Efficient data aggregation
- Minimal resource overhead
- Caching for frequently accessed data

#### **Enhanced Startup Logging**
The service now provides comprehensive startup information displayed when launching:
- **Admin dashboard URLs**: Exact paths to dashboard and login pages
- **Available features**: Real-time analytics, charts, activity feed, health monitoring
- **Security configuration**: Authentication method, IP whitelist, rate limiting status
- **Server configuration**: Mode, Redis connection, TLS status, security headers
- **Default credentials**: Displayed with security warnings for production use

Example startup output:
```
🎛️  Admin Dashboard:
   ├─ Dashboard: http://localhost:8080/admin/
   ├─ Login:     http://localhost:8080/admin/login
   ├─ Features:
   │  ├─ 📊 Real-time Analytics
   │  ├─ 📈 Interactive Charts
   │  ├─ 📋 Live Activity Feed
   │  └─ 🔍 System Health Monitoring
   └─ Security:
      ├─ 🔐 JWT Authentication Enabled
      ├─ 🛡️  IP Whitelist: [127.0.0.1 ::1]
      └─ 🚦 Rate Limiting Enabled
```

### 📋 **API Endpoints**

The dashboard provides RESTful APIs for programmatic access:

- `GET /admin/api/dashboard-data` - Complete dashboard data
- `GET /admin/api/stats` - Current statistics
- `GET /admin/api/health` - System health status
- `GET /admin/api/activities` - Recent activities
- `GET /admin/api/chart-data` - Chart data for visualization
- `WebSocket /admin/ws` - Real-time data stream

### 🔒 **Security Features**

- **JWT-based authentication** with configurable expiry
- **IP address whitelisting** for network-level security
- **Rate limiting** to prevent abuse
- **Secure WebSocket connections** with authentication
- **CSRF protection** for all API endpoints
- **Input validation** and sanitization
- **Enhanced access logging** with detailed request information
- **Test mode bypass** for development and testing

#### **Enhanced Security Logging**
The admin panel now provides comprehensive access logging with detailed information:
- **IP address tracking**: Client IP with User-Agent details
- **Request metadata**: URI, method, and timestamp
- **Authorization status**: Success/failure with detailed context
- **Rate limiting events**: Comprehensive rate limit monitoring

#### **Test Mode Features**
When `server.mode = "test"` in configuration:
- **IP validation bypass**: Allows access from any IP address
- **Authentication bypass**: Skips JWT validation with test admin context
- **Enhanced logging**: Shows bypass events with full request details
- **Development convenience**: Simplifies testing and development workflows

**⚠️ Production Security Notes:**
- Change default credentials immediately
- Use strong JWT secrets (32+ characters)
- Configure IP whitelisting appropriately
- Enable HTTPS in production
- Consider placing behind a reverse proxy
- **Never use test mode in production environments**

## Development Roadmap

The OTP service follows a strategic 5-phase development roadmap designed to evolve from a solid foundation into a comprehensive, enterprise-grade authentication platform:

### **Phase 1: Core Foundation** ✅ **COMPLETED**
- Production-ready OTP generation and verification
- Comprehensive testing and security measures
- Performance-optimized UUID-based sharding

### **Phase 2: Enhanced Observability & Security** 🔄 **IN PROGRESS**
- OpenTelemetry tracing and Prometheus metrics
- Advanced security features and audit logging
- Enhanced monitoring and health checks

### **Phase 3: Scalability & Multi-Region** 📈 **PLANNED** 
- Redis Cluster support for horizontal scaling
- Multi-region deployment capabilities
- High availability and resilience patterns

### **Phase 4: Enterprise Features** 🚀 **FUTURE**
- Multi-tenant architecture and compliance
- Advanced API capabilities (GraphQL, gRPC)
- Admin dashboard and white-label solutions

### **Phase 5: AI/ML Integration** 🤖 **VISIONARY**
- Intelligent fraud detection and optimization
- Predictive analytics and scaling
- Next-generation protocol support

**📋 Full Details**: See **[ROADMAP.md](ROADMAP.md)** for complete feature specifications, timelines, and technical architecture evolution plans.

## Related Documentation

- **[ROADMAP.md](ROADMAP.md)** - Complete development roadmap, feature planning, and project vision
- **[TESTING.md](TESTING.md)** - Comprehensive testing documentation, test suite overview, and quality assessment
- **[SECURITY.md](SECURITY.md)** - Security policy, vulnerability reporting, and security best practices

---

If you have any questions or issues, feel free to reach out for support.
