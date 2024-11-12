# Dockerfile for OTP Service

# Use the official Golang image to create a binary.
FROM golang:latest AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN GOOS=linux GOARCH=amd64 go build -o otp-service

# Use a minimal image to run the service
FROM alpine:latest

# Install required libraries
RUN apk --no-cache add ca-certificates libc6-compat bash

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the pre-built binary file from the builder
COPY --from=builder /app/otp-service .

# Copy the config file
COPY config.yaml .

# Make the binary executable
RUN chmod +x otp-service

# Expose the port that the service will run on
EXPOSE 8080

# Run the OTP service binary
CMD ["./otp-service"]