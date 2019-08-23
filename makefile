SOURCES := $(shell find . -name '*.go')
BINARY := windows-bench.exe
VERSION ?= "1.1.0"
TARGET_OS := windows
BUILD_OS := windows

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=$(TARGET_OS) GO111MODULE=on CGO_ENABLED=0 go build -ldflags "-X github.com/aquasecurity/windows-bench/cmd.windowsCisVersion=$(VERSION)" -o $(BINARY) .

tests:
	GO111MODULE=on go test -v -short -race -timeout 30s -coverprofile=coverage.txt -covermode=atomic ./...
