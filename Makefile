VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# Windows ships two binaries from the same source: dotvault.exe (Console
# subsystem, behaves like a normal CLI under cmd.exe / PowerShell) and
# dotvaultw.exe (GUI subsystem, for double-click + tray with no console).
# The PE subsystem flag is immutable post-link, so we build twice.
WINDOWS_GUI_LDFLAGS := -ldflags "-s -w -H=windowsgui -X main.version=$(VERSION)"

# Windows .exe icon: rsrc emits a COFF object (*.syso) into cmd/dotvault/.
# Go's build picks it up automatically for Windows targets thanks to the
# _windows_amd64 suffix and ignores it for other platforms. The file is
# regenerated from assets/dotvault.ico whenever the icon changes; .syso
# is a build artefact and excluded from version control.
WINDOWS_ICON_SYSO := cmd/dotvault/rsrc_windows_amd64.syso

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

build-windows-amd64-cli: $(WINDOWS_ICON_SYSO)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/dotvault-windows-amd64.exe ./cmd/dotvault

build-windows-amd64-gui: $(WINDOWS_ICON_SYSO)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(WINDOWS_GUI_LDFLAGS) -o dist/dotvaultw-windows-amd64.exe ./cmd/dotvault

$(WINDOWS_ICON_SYSO): assets/dotvault.ico
	go tool rsrc -arch amd64 -ico $< -o $@

.PHONY: clean
clean:
	rm -rf dist/ $(WINDOWS_ICON_SYSO)
