# Set the default goal
.DEFAULT_GOAL := build

# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on

# Disable CGO
export CGO_ENABLED=0

SOURCES := $(shell find . -name '*.go')
IMAGE_TAG := dev
OPERATOR_IMAGE := aquasec/starboard-operator:$(IMAGE_TAG)
SCANNER_IMAGE := aquasec/starboard-scanner-aqua:$(IMAGE_TAG)

.PHONY: modules
modules:
	go mod tidy

build: operator scanner

scanner: $(SOURCES)
	GOOS=linux go build -o bin/scanner cmd/scanner/main.go

operator: $(SOURCES)
	GOOS=linux go build -o bin/operator cmd/operator/main.go

.PHONY: test
test:
	CGO_ENABLED=1 go test -v -short -race -coverprofile=coverage.txt -covermode=atomic ./...

docker-build: docker-build-operator docker-build-scanner

docker-build-operator: build
	docker build --no-cache -t $(OPERATOR_IMAGE) -f Dockerfile.operator bin

docker-build-scanner: build
	docker build --no-cache -t $(SCANNER_IMAGE) -f Dockerfile.scanner bin
