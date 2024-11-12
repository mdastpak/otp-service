
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
  -d '{
    "ttl": 120,
    "retry_limit": 3,
    "code_length": 8,
    "strict_validation": true,
    "use_alpha_numeric": true
  }'
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

**URL**: `/:uuid/:otp`

**Method**: `GET`

**Description**: Verifies an OTP based on the UUID and OTP value provided.

#### Path Parameters

- `uuid` (required): The UUID associated with the OTP that was generated.
- `otp` (required): The OTP value to be verified.

#### Example Request

```bash
curl -X GET "http://localhost:8080/1c11604d-47fa-442a-866a-231686e14a8b/447317"
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
    "redis_status": "OK"
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

| Status Code | Message                  | Description                                          |
| ----------- | ------------------------ | ---------------------------------------------------- |
| `200`     | `OTP_GENERATED`        | OTP was successfully generated.                      |
| `200`     | `OTP_VERIFIED`         | OTP was successfully verified.                       |
| `400`     | `REQUEST_BODY_INVALID` | The request body is invalid or improperly formatted. |
| `400`     | `JSON_INVALID`         | The JSON structure is invalid.                       |
| `400`     | `TTL_INVALID`          | The `ttl` parameter is out of range.               |
| `400`     | `RETRY_INVALID`        | The `retry_limit` parameter is out of range.       |
| `400`     | `CODE_INVALID`         | The `code_length` parameter is out of range.       |
| `400`     | `OTP_MISSING`          | Required UUID or OTP is missing from request.        |
| `401`     | `OTP_INVALID`          | The provided OTP is incorrect.                       |
| `401`     | `OTP_EXPIRED`          | The OTP has expired.                                 |
| `401`     | `OTP_ATTEMPTS`         | The OTP retry limit has been reached.                |
| `401`     | `REQUEST_MISMATCH`     | The request body does not match the expected data.   |
| `500`     | `SERVICE_HEALTH`       | Health check of the service, including Redis status. |

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
curl --silent --location --request GET 'localhost:8080/e63ee3c4-9ebe-42a3-8c2a-e05e88c468a4/174464' \
--header 'Content-Type: application/json' \
--data '{}'
```

#### Example 5: Verify OTP with Strict Validation Enabled

```bash
curl --silent --location --request GET 'localhost:8080/f49c8bb4-e88e-453e-a878-b69c42c0a32a/720041' \
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

If you have any questions or issues, feel free to reach out for support.
