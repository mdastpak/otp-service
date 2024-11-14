# OTP Service API Documentation

This README provides details on the API endpoints, input parameters, expected request/response bodies, and status codes for the OTP (One-Time Password) service.

## Table of Contents

- [Endpoints](#endpoints)
  - [Generate OTP](#generate-otp)
  - [Verify OTP](#verify-otp)
  - [Health Check](#health-check)
- [Request Parameters](#request-parameters)
- [Response Structure](#response-structure)
- [Status Code Guide](#status-code-guide)
- [Configuration Indices](#configuration-indices)

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

- **Single Index**: You can specify a single Redis index (e.g., `0`) to store all OTPs in a single Redis database.
- **Range of Indices**: You can specify a range of Redis indices (e.g., `0-3`). In this scenario, OTPs will be distributed among the specified Redis databases using a round-robin algorithm, which helps to balance the load.

The `REDIS.INDICES` configuration is crucial for scaling the OTP service effectively, especially under high load. By distributing the OTPs across multiple Redis databases, the service can handle more concurrent requests and reduce contention for Redis resources.

The `REDIS.KEY_PREFIX` configuration allows you to set a prefix for all Redis keys used by the service. This can be useful for namespacing keys, especially if you are using a shared Redis instance for multiple services. If left empty (`""`), no prefix will be added. Example: if the prefix is set to `"OTP"`, all keys will be stored as `"OTP:<key>"`.

The `REDIS.TIMEOUT` configuration allows you to set a timeout for Redis connections. This is useful for ensuring that the service does not get stuck waiting for a Redis connection that is not responding. The default value is `5s`.

### Additional Configuration Parameters

The OTP service also provides additional configuration parameters that can be adjusted in the `CONFIG` section of the configuration file.

- **`CONFIG.HASH_KEY`**: If set to `true`, the Redis keys used to store OTPs are hashed using SHA-256. This helps to prevent any potential key collisions and makes the keys more secure. It is recommended to keep this value as `true` for production environments.
- **`SERVER.DEBUG`**: If set to `true`, the service will log additional debug information, which can be helpful for troubleshooting. It is recommended to keep this value as `false` for production environments.

If you have any questions or issues, feel free to reach out for support.
