# Installation

## Pre-built binaries

Download the latest release for your platform from the [GitHub Releases](https://github.com/goodtune/dotvault/releases) page.

Binaries are available for:

| OS      | Architecture |
|---------|-------------|
| Linux   | amd64, arm64 |
| macOS   | amd64, arm64 |
| Windows | amd64        |

All binaries are statically compiled (no CGO dependencies) and require no runtime libraries.

## Build from source

Requirements:

- Go 1.25 or later
- Node.js (for building the web frontend)
- Make

```sh
git clone https://github.com/goodtune/dotvault.git
cd dotvault
make build
```

To cross-compile for all supported platforms:

```sh
make build-all
```

### Building the web frontend

If you modify the web UI, rebuild the frontend assets before compiling:

```sh
cd internal/web/frontend && npm run build
cd -
make build
```

The built frontend assets are embedded into the binary via Go's `embed.FS`, so the final binary is fully self-contained.

## Verify the installation

```sh
dotvault version
```
