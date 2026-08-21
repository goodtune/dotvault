# Build and packaging internals

> Carved from CLAUDE.md. Version injection, the Windows two-binary split, and the `VS_VERSIONINFO` resource pipeline.

## Build & Test

```sh
make test          # run all tests
make python-test   # build the cgo bridge, then run the Python binding tests
make build         # build for current platform
make build-all     # cross-compile linux/darwin (amd64/arm64) and windows (amd64)
```

All builds use `CGO_ENABLED=0` for static binaries. Version is injected via ldflags (`-X main.version=...`). Release tags are `v`-prefixed (`v0.19.0`) for Go-module consumption, but `main.version` is the v-stripped semantic version (`0.19.0`): GoReleaser's `{{.Version}}` strips the prefix and the Makefile strips it via `sed`, so local and release builds agree. Consumers (the `version` command, `/api/v1/status`, the OTel `service.version` attribute and the `dotvault.build_info` gauge's `version` attribute, the tray tooltip, and the web UI header which prepends its own `v`) treat the value as v-stripped and must not add or assume a leading `v`.

Windows ships two binaries from the same source — the PE subsystem flag is immutable post-link, so the only correct fix is to build twice:

- `dotvault.exe` — Console subsystem. The CLI for `sync`, `status`, `run` (foreground daemon), `reg-export`/`reg-import`, etc. cmd.exe / PowerShell wait for it, stdio is inherited, Ctrl+C works. Bare invocation prints help.
- `dotvaultw.exe` — GUI subsystem (`-H=windowsgui`). For double-click. Runs the daemon with the system-tray icon and no console flash. Bare invocation defaults to the daemon (equivalent to `dotvault run`) because there's no console to show help on; this is detected at runtime via `os.Args[0]`. CLI subcommands invoked through it will appear to do nothing because cmd.exe does not wait for GUI-subsystem binaries — use `dotvault.exe` for CLI work.

Installer / Start Menu shortcuts should point at `dotvaultw.exe`; the PATH entry should be `dotvault.exe`.

Both Windows binaries embed the application icon **and** a `VS_VERSIONINFO` resource (the latter is what populates Explorer's right-click → Properties → Details tab: File version, Product version, Company, File description, Copyright). `assets/dotvault.ico` is the multi-resolution source (16/24/32/48/64/128/256, generated from `assets/dotvault-no-text.png`); `assets/versioninfo.json` holds the static string metadata. The Makefile and the `.goreleaser.yml` `before:` hook run `go tool goversioninfo` (replacing the icon-only `go tool rsrc`) to emit `cmd/dotvault/rsrc_windows_amd64.syso`, which the Go linker picks up automatically for `windows_amd64` targets and ignores everywhere else. The version is injected at generation time, not stored in the JSON: the full v-stripped `VERSION` string fills the string `FileVersion`/`ProductVersion` fields, and its `major.minor.patch` core (with build `0`, falling back to `0.0.0` for an untagged build) fills the numeric `FixedFileInfo` block, which requires four 16-bit integers. Both binaries are built from `cmd/dotvault`, so the single `.syso` is linked into each — they carry identical version metadata and share the static `OriginalFilename` string (`dotvault.exe`). The `.syso` is a build artefact (regeneratable, gitignored). The system-tray code in `internal/tray/tray_windows.go` loads the icon by resource ID rather than the stock `IDI_APPLICATION`, so the tray, taskbar, and Start Menu shortcuts all carry the dotvault glyph; if the resource is missing (e.g. a hand-rolled `go build` skipping the `.syso`) the tray falls back to the system default.

The web UI is server-rendered Go templates with no build step: templates in `internal/web/uitmpl/*.tmpl` and static assets in `internal/web/uiassets/` are embedded via `embed.FS`, so editing either only needs a rebuild of the binary. There is no npm toolchain in this repo (the Preact SPA that used to live in `internal/web/frontend/` was removed when the server-rendered UI became the only surface).

