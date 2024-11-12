# Stage 1: Build
FROM golang:latest AS builder

WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o otp_service

# Stage 2: Run
FROM alpine:latest

WORKDIR /root/

# Install necessary packages
RUN apk --no-cache add ca-certificates

# Copy the binary from the builder stage
COPY --from=builder /app/otp_service .

# Copy configuration files
COPY config.yaml .
COPY i18n/ ./i18n/

# Set environment variables (if any)
ENV GIN_MODE=release

# Expose the port the service will run on
EXPOSE 8080

# Run the application
CMD ["./otp_service"]
