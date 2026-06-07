# Strip a leading "v" from the tag so the injected main.version matches what
# GoReleaser produces ({{.Version}} is always v-stripped). Tags are v-prefixed
# (v0.19.0) for Go-module consumption; the binary version string is not, so the
# web UI (which prepends its own "v") and packaging stay consistent across the
# local-build and release paths.
VERSION := $(shell git describe --tags --always --dirty | sed 's/^v//')
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# Windows ships two binaries from the same source: dotvault.exe (Console
# subsystem, behaves like a normal CLI under cmd.exe / PowerShell) and
# dotvaultw.exe (GUI subsystem, for double-click + tray with no console).
# The PE subsystem flag is immutable post-link, so we build twice.
WINDOWS_GUI_LDFLAGS := -ldflags "-s -w -H=windowsgui -X main.version=$(VERSION)"

# Windows .exe resources: goversioninfo emits a COFF object (*.syso) into
# cmd/dotvault/ carrying both the application icon and a VS_VERSIONINFO
# resource (the latter populates Explorer's Details tab — File version,
# Product version, Company, Description). Go's build picks the .syso up
# automatically for Windows targets thanks to the _windows_amd64 suffix and
# ignores it for other platforms. The file is regenerated whenever the icon,
# the static metadata (assets/versioninfo.json), or the version changes; .syso
# is a build artefact and excluded from version control.
#
# Both Windows binaries are built from cmd/dotvault, so the Go linker embeds
# this single .syso into each — dotvault.exe and dotvaultw.exe therefore carry
# identical version metadata (the point of the exercise) and share the static
# OriginalFilename string.
WINDOWS_SYSO := cmd/dotvault/rsrc_windows_amd64.syso

# VS_VERSIONINFO FixedFileInfo requires four 16-bit integers, so split the
# semver core off the (possibly "-N-gSHA-dirty") describe string and fall back
# to 0.0.0 for an untagged build. The full descriptive VERSION still lands in
# the string FileVersion/ProductVersion fields.
WINDOWS_VERSION_PARTS := $(shell printf '%s' "$(VERSION)" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || printf '0.0.0')
WINDOWS_VER_MAJOR := $(word 1,$(subst ., ,$(WINDOWS_VERSION_PARTS)))
WINDOWS_VER_MINOR := $(word 2,$(subst ., ,$(WINDOWS_VERSION_PARTS)))
WINDOWS_VER_PATCH := $(word 3,$(subst ., ,$(WINDOWS_VERSION_PARTS)))

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

build-windows-amd64-cli: $(WINDOWS_SYSO)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/dotvault-windows-amd64.exe ./cmd/dotvault

build-windows-amd64-gui: $(WINDOWS_SYSO)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(WINDOWS_GUI_LDFLAGS) -o dist/dotvaultw-windows-amd64.exe ./cmd/dotvault

$(WINDOWS_SYSO): assets/dotvault.ico assets/versioninfo.json
	go tool goversioninfo -64 -icon assets/dotvault.ico \
		-file-version "$(VERSION)" -product-version "$(VERSION)" \
		-ver-major $(WINDOWS_VER_MAJOR) -ver-minor $(WINDOWS_VER_MINOR) -ver-patch $(WINDOWS_VER_PATCH) -ver-build 0 \
		-product-ver-major $(WINDOWS_VER_MAJOR) -product-ver-minor $(WINDOWS_VER_MINOR) -product-ver-patch $(WINDOWS_VER_PATCH) -product-ver-build 0 \
		-o $@ assets/versioninfo.json

.PHONY: clean
clean:
	rm -rf dist/ $(WINDOWS_SYSO)
