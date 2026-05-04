VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# Windows ships two binaries from the same source: dotvault.exe (Console
# subsystem, behaves like a normal CLI under cmd.exe / PowerShell) and
# dotvaultw.exe (GUI subsystem, for double-click + tray with no console).
# The PE subsystem flag is immutable post-link, so we build twice.
WINDOWS_GUI_LDFLAGS := -ldflags "-s -w -H=windowsgui -X main.version=$(VERSION)"

.PHONY: test
test:
	go test ./...

.PHONY: build
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o dist/dotvault ./cmd/dotvault

.PHONY: build-all
build-all: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/dotvault-linux-amd64 ./cmd/dotvault

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/dotvault-linux-arm64 ./cmd/dotvault

build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/dotvault-darwin-amd64 ./cmd/dotvault

build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/dotvault-darwin-arm64 ./cmd/dotvault

build-windows-amd64: build-windows-amd64-cli build-windows-amd64-gui

build-windows-amd64-cli:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/dotvault-windows-amd64.exe ./cmd/dotvault

build-windows-amd64-gui:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(WINDOWS_GUI_LDFLAGS) -o dist/dotvaultw-windows-amd64.exe ./cmd/dotvault

.PHONY: clean
clean:
	rm -rf dist/
