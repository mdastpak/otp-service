# Build stage
FROM golang:latest-alpine AS builder

# Install required packages
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/server/main.go

# Final stage
FROM alpine:3.18

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -S app && adduser -S app -G app

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/main .
# Copy config files
COPY --from=builder /app/config/config.yaml ./config/

# Use non-root user
USER app

# Command to run
ENTRYPOINT ["./main"]