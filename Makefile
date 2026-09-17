# go-auth-client

.DEFAULT_GOAL := help

## help: list the available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | awk -F: '{printf "  \033[36m%-14s\033[0m%s\n", $$1, $$2}'

## test: run the test suite
test:
	go test ./... -count=1

## test-v: run the test suite, naming each test
test-v:
	go test ./... -count=1 -v

## race: run the suite under the race detector (do this before pushing)
race:
	go test ./... -count=1 -race

## cover: run tests and open the coverage report
cover:
	go test ./... -count=1 -coverprofile=coverage.out
	go tool cover -html=coverage.out

## vet: run go vet
vet:
	go vet ./...

## check: format, vet, and run the suite under the race detector
check: tidy vet race

## tidy: format the code and prune go.mod
tidy:
	gofmt -w .
	go mod tidy

## example: run the example service (needs AUTH_URL and a running auth service)
example:
	AUTH_URL=$${AUTH_URL:-http://localhost:8080} go run ./examples/orders-service

.PHONY: help test test-v race cover vet check tidy example
