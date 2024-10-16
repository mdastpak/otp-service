# OTP Generation and Verification System

This is a Go-based OTP (One-Time Password) generation and verification system that uses Redis as the backend for storing OTPs. The system supports both numeric and alphanumeric OTPs, with configurable TTL (time-to-live), retry limits, and validation modes.

## Features

- Generate and validate OTP codes.
- Configurable TTL and retry limits.
- Support for numeric and alphanumeric OTP codes.
- Supports strict body validation during OTP verification.
- Redis is used for fast and reliable storage of OTP data.

## Endpoints

### 1. Generate OTP (`POST /otp`)

Generate a one-time password (OTP) with configurable parameters like TTL, retry limits, and code complexity.

**Query Parameters, Defaults, and Valid Ranges:**

- `strict_validation` (bool): Whether to enable strict validation of request bodies during OTP verification.
  - Accepted values: **true/false or 1/0**.
  - Default: **false**.
- `ttl` (int): Time-to-live for the OTP, in seconds.
  - Valid range: **1 to 3600**.
  - Default: **60** seconds.
- `retry_limit` (int): Number of allowed retries for OTP verification.
  - Valid Range: **1-10**.
  - Default: **5** retries.
- `use_alpha_numeric` (bool): Whether to generate an alphanumeric OTP.
  - Accepted values: **true/false or 1/0**.
  - Default: **false**.
- `code_length` (int): Length of the OTP code.
  - Valid Range: **1-10**.
  - Default: **6** characters.

**Request Example (cURL):**

```bash
curl --silent --location --request POST '127.0.0.1:8080/otp?strict_validation=false&ttl=60&retry_limit=5&use_alpha_numeric=false&code_length=6' \
--header 'Content-Type: application/json' \
--data '{
    "Hi": "Welcome",
    "key": {
        "value":"1",
        "value2": "2"
    }
}'
```

### 2. Verify OTP (`GET /otp`)

Verify the OTP code provided by the user and optionally perform strict validation of the request body.

**Query Parameters:**

- `uuid` (string): The unique identifier for the OTP request.
- `otp` (string): The OTP code to verify.

**Request Example (cURL):**

```bash
curl --silent --location --request GET '127.0.0.1:8080/verify?uuid=1c9db35c-0078-4c85-bb9a-f67cf8db9564&otp=440757' \
--header 'Content-Type: application/json' \
--data '{
    "Hi": "Welcome",
    "key": {
        "value":"4",
        "value2": "2"
    }
}'
```
