# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=otp-service
BINARY_UNIX=$(BINARY_NAME)_unix
GOPROXY=direct

# Build targets
.PHONY: all build clean test coverage benchmark deps run docker-build docker-run lint fmt vet

all: test build

build:
	$(GOBUILD) -o $(BINARY_NAME) -v ./main.go

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) -v ./main.go

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_UNIX)

test:
	$(GOTEST) -v ./internal/...
	$(GOTEST) -v . -timeout=30s

test-all: 
	./run_tests.sh

test-short:
	$(GOTEST) -short -v ./internal/...

coverage:
	$(GOTEST) -coverprofile=coverage.out ./internal/...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	$(GOCMD) tool cover -func=coverage.out

benchmark:
	$(GOTEST) -bench=. -benchmem ./internal/...

deps:
	$(GOMOD) download
	$(GOMOD) tidy

run:
	$(GOBUILD) -o $(BINARY_NAME) -v ./main.go
	./$(BINARY_NAME)

run-old:
	$(GOBUILD) -o $(BINARY_NAME)_old -v ./main.go
	./$(BINARY_NAME)_old

docker-build:
	docker build -t $(BINARY_NAME):latest .

docker-run:
	docker-compose up --build

lint:
	golangci-lint run ./...

fmt:
	$(GOCMD) fmt ./...

vet:
	$(GOCMD) vet ./...

# Security scanning
security:
	gosec ./...

# Generate mock files (if using mockgen)
generate:
	$(GOCMD) generate ./...

# Install tools
install-tools:
	$(GOGET) -u github.com/golangci/golangci-lint/cmd/golangci-lint
	$(GOGET) -u github.com/securecodewarrior/gosec/v2/cmd/gosec

# Run all checks
check: fmt vet test lint

# Help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  build-linux   - Build for Linux"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  test-short    - Run short tests"
	@echo "  coverage      - Generate test coverage report"
	@echo "  benchmark     - Run benchmarks"
	@echo "  deps          - Download dependencies"
	@echo "  run           - Build and run (new version)"
	@echo "  run-old       - Build and run (old version)"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run with docker-compose"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  vet           - Run go vet"
	@echo "  security      - Run security scanner"
	@echo "  check         - Run all checks"
	@echo "  help          - Show this help"