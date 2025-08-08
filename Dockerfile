# Multi-stage Docker build for OTP Service
# Stage 1: Build the application
FROM golang:1.23.2-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files first (for better Docker layer caching)
COPY go.mod go.sum ./

# Download dependencies
ENV GOPROXY=direct
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o otp-service ./main.go

# Stage 2: Create the final runtime image
FROM scratch

# Copy certificates and timezone data from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the pre-built binary file from the builder
COPY --from=builder /app/otp-service /otp-service

# Copy the config file
COPY --from=builder /app/config.yaml /config.yaml

# Create a non-root user
USER 65534:65534

# Expose the port that the service will run on
EXPOSE 8080

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/otp-service", "--healthcheck"] || exit 1

# Run the OTP service binary
ENTRYPOINT ["/otp-service"]