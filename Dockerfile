# Simple Docker build for OTP Service
FROM golang:1.24-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Configure Go proxy
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org

# Download dependencies
RUN go mod download

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

# Copy binary
COPY --from=builder /app/otp-service /otp-service

# Create directories
RUN mkdir -p /app/logs && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=5 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/otp-service"]