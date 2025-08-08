# Makefile for OTP Service
.PHONY: help build test start stop clean

help: ## Show help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "%-20s %s\n", $$1, $$2}'

build: ## Build Docker image (test mode - default)
	./scripts/build.sh -e test

build-prod: ## Build production Docker image
	./scripts/build.sh -e production

test: ## Run all tests
	go test -v -race ./...
	@echo "Running integration tests with Redis..."
	docker-compose up -d redis
	sleep 5
	go test -v -race ./tests/ -run "TestBasic" || true
	docker-compose down

test-unit: ## Run unit tests only
	go test -v -race ./internal/...

test-integration: ## Run basic integration tests
	docker-compose up -d redis
	sleep 5
	go test -v -race ./tests/ -run "TestBasic"
	docker-compose down

test-security: ## Run security tests
	docker-compose up -d redis
	sleep 5
	go test -v -race ./tests/ -run "TestSecurity"
	docker-compose down

test-env: ## Run environment-specific tests  
	docker-compose up -d redis
	sleep 5
	go test -v -race ./tests/ -run "TestProduction"
	docker-compose down

test-coverage: ## Run tests with coverage
	go test -v -race -coverprofile=coverage.out ./...
	docker-compose up -d redis
	sleep 5
	go test -v -race -coverprofile=coverage-tests.out ./tests/ || true
	docker-compose down
	go tool cover -html=coverage.out -o coverage.html

start: ## Start test services (default mode)
	docker-compose up -d

start-prod: ## Start production services
	docker-compose -f docker-compose.yml -f docker-compose.production.yml up -d

stop: ## Stop services
	docker-compose down

logs: ## View logs
	docker-compose logs -f

clean: ## Clean Docker resources
	docker-compose down --rmi local --volumes

.DEFAULT_GOAL := help
EOF < /dev/null