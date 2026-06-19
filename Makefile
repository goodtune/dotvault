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

# The version is injected from VERSION (not stored in the .ico/.json), so it
# must be a prerequisite of the .syso or a VERSION change (new commit/tag) with
# an unchanged icon and JSON would leave a stale resource embedding the wrong
# version. VERSION isn't a file, so this stamp stands in for it: the recipe runs
# every invocation (FORCE) but only rewrites the file — advancing its mtime —
# when the recorded version actually differs, so the .syso regenerates exactly
# when VERSION changes and not on every build.
WINDOWS_VERSION_STAMP := cmd/dotvault/.version-stamp

# VS_VERSIONINFO FixedFileInfo requires four 16-bit integers, so split the
# semver core off the (possibly "-N-gSHA-dirty") describe string and fall back
# to 0.0.0 for an untagged build.
WINDOWS_VERSION_PARTS := $(shell printf '%s' "$(VERSION)" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || printf '0.0.0')
WINDOWS_VER_MAJOR := $(word 1,$(subst ., ,$(WINDOWS_VERSION_PARTS)))
WINDOWS_VER_MINOR := $(word 2,$(subst ., ,$(WINDOWS_VERSION_PARTS)))
WINDOWS_VER_PATCH := $(word 3,$(subst ., ,$(WINDOWS_VERSION_PARTS)))

# The full descriptive VERSION lands in the string FileVersion/ProductVersion
# fields. goversioninfo parses that string even though we pass the numeric block
# explicitly, so an untagged/shallow clone whose describe is a bare hash (no
# leading x.y.z) triggers a "could not be parsed" warning. Prefix such a value
# with 0.0.0- to silence the noise while keeping the hash visible in the Details
# tab; a value already starting with a semver core is used verbatim.
WINDOWS_VERSION_STRING := $(shell printf '%s' "$(VERSION)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+' && printf '%s' "$(VERSION)" || printf '0.0.0-%s' "$(VERSION)")

# Python bindings (python/). The cgo c-shared bridge is the one place dotvault
# builds with CGO_ENABLED=1 — it has to, c-shared requires cgo — and it is a
# separate artefact, so the main binaries above stay CGO_ENABLED=0. The output
# filename carries the platform's shared-library extension; ctypes loads it by
# the _dotvault.* glob regardless.
PY_GOOS := $(shell go env GOOS)
ifeq ($(PY_GOOS),windows)
PY_LIB := _dotvault.dll
else ifeq ($(PY_GOOS),darwin)
PY_LIB := _dotvault.dylib
else
PY_LIB := _dotvault.so
endif

.PHONY: test
test:
	go test ./...

# Build the native bridge into the Python package directory for local use
# (pytest, editable installs). The .h header go emits alongside it is not
# needed at runtime and is removed so it never lands in a wheel.
.PHONY: python-lib
python-lib:
	CGO_ENABLED=1 go build -buildmode=c-shared -o python/src/dotvault/$(PY_LIB) ./python/bridge
	rm -f python/src/dotvault/_dotvault.h

.PHONY: python-test
python-test: python-lib
	cd python && uv run --no-project --with pytest python -m pytest tests/ -q

# Build a platform wheel. setup.py rebuilds the bridge as part of the build, so
# this works from a clean tree; python-lib is not a prerequisite. The wheel is
# tagged py3-none-<platform> (ctypes over a native lib — no CPython ABI), so a
# single wheel per OS serves every supported Python.
.PHONY: python-wheel
python-wheel:
	cd python && uv build --wheel

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

$(WINDOWS_SYSO): assets/dotvault.ico assets/versioninfo.json $(WINDOWS_VERSION_STAMP)
	go tool goversioninfo -64 -icon assets/dotvault.ico \
		-file-version "$(WINDOWS_VERSION_STRING)" -product-version "$(WINDOWS_VERSION_STRING)" \
		-ver-major $(WINDOWS_VER_MAJOR) -ver-minor $(WINDOWS_VER_MINOR) -ver-patch $(WINDOWS_VER_PATCH) -ver-build 0 \
		-product-ver-major $(WINDOWS_VER_MAJOR) -product-ver-minor $(WINDOWS_VER_MINOR) -product-ver-patch $(WINDOWS_VER_PATCH) -product-ver-build 0 \
		-o $@ assets/versioninfo.json

# Rewrite the stamp only when the recorded VERSION differs, so its mtime (and
# thus the .syso) advances exactly on a version change. Depends on FORCE so the
# comparison runs every time; the file is real (not .PHONY) so its timestamp is
# a meaningful prerequisite.
$(WINDOWS_VERSION_STAMP): FORCE
	@printf '%s' '$(VERSION)' | cmp -s - $@ 2>/dev/null || printf '%s' '$(VERSION)' > $@

.PHONY: FORCE
FORCE:

.PHONY: clean
clean:
	rm -rf dist/ $(WINDOWS_SYSO) $(WINDOWS_VERSION_STAMP)
	rm -rf python/build python/dist python/src/dotvault.egg-info
	rm -f python/src/dotvault/_dotvault.*
