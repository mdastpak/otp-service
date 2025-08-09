# Simple Docker build for OTP Service
FROM golang:1.24-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Configure Go proxy with multiple fallbacks
ENV GOPROXY=https://goproxy.cn,https://goproxy.io,https://proxy.golang.org,direct
ENV GOSUMDB=off
ENV GOPRIVATE=""

# Download dependencies with retry logic
RUN go mod download || (sleep 5 && go mod download) || go mod download -x

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o otp-service ./main.go

# Runtime stage
FROM alpine:3.21

# Install runtime dependencies
RUN apk add --no-cache ca-certificates curl tzdata && \
    update-ca-certificates

# Create appuser
RUN adduser -D -g '' appuser

# Copy binary and config
COPY --from=builder /app/otp-service /otp-service
COPY --from=builder /app/config.yaml /config.yaml

# Create directories
RUN mkdir -p /app/logs && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=5 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/otp-service"]