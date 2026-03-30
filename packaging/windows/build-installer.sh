#!/usr/bin/env bash
set -euo pipefail

# Build a Windows NSIS installer from goreleaser output.
#
# Usage:
#   ./packaging/windows/build-installer.sh [version]
#
# If version is omitted, it is read from dist/metadata.json (goreleaser output).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"

# Resolve version
if [ -n "${1:-}" ]; then
  VERSION="$1"
elif [ -f "$DIST_DIR/metadata.json" ]; then
  VERSION="$(python3 -c "import json,sys; print(json.load(open('$DIST_DIR/metadata.json'))['version'])")"
else
  echo "error: no version provided and dist/metadata.json not found" >&2
  echo "usage: $0 [version]" >&2
  exit 1
fi

# Find the Windows binary from goreleaser output
BINARY=""
for candidate in \
  "$DIST_DIR/dotvault_windows_amd64_v1/dotvault.exe" \
  "$DIST_DIR/dotvault_windows_amd64/dotvault.exe"; do
  if [ -f "$candidate" ]; then
    BINARY="$candidate"
    break
  fi
done

if [ -z "$BINARY" ]; then
  echo "error: Windows binary not found in $DIST_DIR" >&2
  exit 1
fi

echo "==> Building Windows installer"
echo "    Version: $VERSION"
echo "    Binary:  $BINARY"

# Stage files for NSIS
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

cp "$BINARY" "$STAGING/dotvault.exe"
cp "$PROJECT_ROOT/LICENSE" "$STAGING/LICENSE"
cp "$PROJECT_ROOT/internal/web/static/favicon.ico" "$STAGING/dotvault.ico"
cp "$SCRIPT_DIR/dotvault.nsi" "$STAGING/dotvault.nsi"

# Stage Group Policy ADMX/ADML templates
cp "$SCRIPT_DIR/dotvault.admx" "$STAGING/dotvault.admx"
mkdir -p "$STAGING/en-US"
cp "$SCRIPT_DIR/en-US/dotvault.adml" "$STAGING/en-US/dotvault.adml"

# Run NSIS
makensis \
  -DAPP_VERSION="$VERSION" \
  -DBINARY=dotvault.exe \
  "$STAGING/dotvault.nsi"

# Move installer to dist/
INSTALLER="$STAGING/dotvault_${VERSION}_windows_amd64_setup.exe"
mv "$INSTALLER" "$DIST_DIR/"

echo "==> Installer: $DIST_DIR/dotvault_${VERSION}_windows_amd64_setup.exe"
