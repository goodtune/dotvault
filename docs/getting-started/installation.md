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

### Web UI assets

The web UI is server-rendered: its Go templates and static assets are embedded into the binary via Go's `embed.FS`, so there is no separate asset build and the final binary is fully self-contained. Editing a template or stylesheet only needs `make build`.

## Verify the installation

```sh
dotvault version
```
