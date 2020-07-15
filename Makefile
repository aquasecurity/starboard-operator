SOURCES := $(shell find . -name '*.go')
BINARY := operator
IMAGE_TAG := dev
IMAGE := aquasec/starboard-security-operator:$(IMAGE_TAG)

build: $(BINARY)

test: build
	GO111MODULE=on go test -v -short -race -coverprofile=coverage.txt -covermode=atomic ./...

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/manager/main.go

docker-build: build
	docker build --no-cache -t $(IMAGE) -f Dockerfile bin
