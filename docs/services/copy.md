# Copy Onboarding

The `copy` enrolment engine mirrors an existing Vault KVv2 secret into the user's enrolment path, optionally reshaping it through a Go template. It is the right choice when another tool (or an operator workflow) already populates a per-user secret under a shared prefix and dotvault needs to expose that value to the user under their own path — usually with different field names — without re-running an interactive flow.

Unlike the OAuth and key-generation engines, the copy engine is fully automated: there is no browser flow, no terminal prompt, and no clipboard handoff. The first invocation runs synchronously like any other enrolment, and after that the daemon's `WatchManager` keeps the target in sync whenever the source changes.

## Configuration

### Minimal

```yaml
enrolments:
  sample:
    engine: copy
    settings:
      from:
        mount: kv
        path: "apps/sample/keys/{{.user}}"
      format: json
      template: |
        {
          "token": "{{ .data.key }}"
        }

rules:
  - name: sample
    vault_key: "sample"
    target:
      path: "~/.config/sample/credentials"
      format: text
      template: "{{ .token }}"
```

With the example above, an operator who populates `kv/apps/sample/keys/alice` (with a field `key`) makes the value available to user `alice` at `kv/users/alice/sample` under the field `token`, which the sync rule then writes to disk.

### Renaming several fields at once

```yaml
enrolments:
  artifactory-readonly:
    engine: copy
    settings:
      from:
        mount: kv
        path: "shared/artifactory/{{.user}}"
      format: json
      template: |
        {
          "username": "{{ .data.user }}",
          "password": "{{ .data.api_key }}",
          "url": "{{ .data.url }}"
        }
```

## Settings reference

| Setting | Default | Description |
|---------|---------|-------------|
| `from.mount` | _(required)_ | KV mount of the source secret (e.g. `kv`) |
| `from.path` | _(required)_ | Path of the source secret. Supports a `{{.user}}` substitution that resolves to the local OS username (`paths.Username()`, with any `DOMAIN\` prefix stripped) |
| `format` | `json` | Output format. Only `json` is currently supported — anything else is rejected at run time |
| `template` | _(required)_ | Go template that renders a JSON object. Top-level keys of the rendered object become the fields written to Vault |

The template receives two top-level values as dot context:

| Reference | Description |
|-----------|-------------|
| `.data` | The source secret's data map. Access individual fields as `{{ .data.fieldname }}` |
| `.user` | The local OS username (same value used to substitute `{{.user}}` in `from.path`). In deployments where the Vault identity differs from the OS login, this is the OS-side login, not `token_meta_username` |

The engine wraps `text/template`, so the same helpers documented in [Templates](../configuration/templates.md) (`env`, `base64encode`, `base64decode`, `default`, `quote`) are available inside the copy template as well.

## How it works

1. The manager resolves the source path by substituting `{{.user}}` for the local OS username (so a single config line covers every user)
2. dotvault reads the source secret from Vault using the daemon's own token — the user must therefore have read permission on the source path
3. The template is executed with `{"data": <source data>, "user": <username>}` as dot context
4. The rendered output is parsed as a JSON object. Each top-level key becomes a field to write; non-string values are coerced to their JSON textual form
5. The target enrolment path is read. Any existing keys are preserved unless the template explicitly overwrites them
6. The merged map is written back to Vault, creating a new KVv2 version

### Merge, don't replace

The target secret is **merged**, not overwritten:

- Keys produced by the template are written (overwriting any existing value with the same name)
- Pre-existing keys at the target path that the template does **not** name are preserved

The completeness check for the enrolment looks only at the fields the template emits, so the engine never reports "incomplete" because of fields it does not own — letting an unrelated operator process maintain a separate field at the same Vault path without confusing the wizard.

!!! warning "No CAS — concurrent writers can clobber each other"
    The merge is not a compare-and-swap. The engine reads the current target, computes the merged result, and writes back via `KVv2.Put` without checking that the version has not changed in between. Any field a third party writes to the target path between the read and the write will be lost on the next copy refresh. The "merge, don't replace" guarantee therefore covers same-version snapshots and non-concurrent writers only; if you need stronger co-tenancy, drive the other writer through a workflow that runs while the daemon is paused, or partition fields so only one process ever writes a given path.

!!! warning "Stringified preservation"
    Preserved values are stringified, not type-preserved. The engine returns `map[string]string`, so any pre-existing object, number, or boolean field at the target is JSON-marshalled to its textual form before being written back. This is intentional (dropping non-strings would lose data) but means the copy engine should not share a target path with workflows that depend on KVv2 fields keeping their original JSON type.

### Dynamic field set

Most engines declare a static list of fields they write via `Fields()`. The copy engine cannot — the field set is whatever the template produces. The engine implements the optional `SettingsFielder` interface instead, parsing the template source (with `{{ ... }}` actions replaced by `null`) to infer the top-level JSON keys without executing it. The manager treats the enrolment as complete only when every inferred key is present in the target secret.

If the template is missing, syntactically invalid JSON, or has actions inside quoted-string arguments containing literal `}}`, field inference falls back to `nil` and the manager treats the enrolment as incomplete on every cycle — surfacing the misconfiguration rather than silently skipping it.

### Periodic re-evaluation

The engine implements the `Watcher` interface, so the daemon's `WatchManager` keeps the target in sync after the initial enrolment:

- **Poll cycle** — on every tick of the configured sync interval, the manager re-runs the engine and writes back only when the merged result differs from the current target. Identical evaluations are skipped, so KVv2 versions are not bumped spuriously.
- **Event-driven refresh (Vault Enterprise)** — the manager subscribes to the `kv-v2/data-write` event type, filters events client-side against the resolved `from.mount`/`from.path` for each copy enrolment, and triggers an immediate refresh on a match. Subscription failures degrade gracefully to poll-only, mirroring the sync engine's reconnection behaviour.

Per-enrolment exponential backoff isolates a single flaky upstream from blocking the others.

## Credentials stored in Vault

There is no fixed list — the engine writes exactly the top-level keys produced by your template, plus any pre-existing keys at the target path. For example, with:

```yaml
template: |
  {
    "username": "{{ .data.user }}",
    "password": "{{ .data.api_key }}"
  }
```

dotvault writes the fields `username` and `password` at the target enrolment path. The completeness check expects exactly those two fields, regardless of what the source secret contains.

## Requirements

- The dotvault daemon's Vault token must have read permission on the source mount and path
- The source secret must already exist when the enrolment runs — the engine does not create source secrets, only consumes them. Missing source secrets fail the enrolment with a clear error
- Only `json` is supported for `format`. YAML / INI / TOML / text / netrc targets are out of scope: copy is for reshaping structured KV data, and JSON is the only round-trippable representation that aligns with KVv2's data model

## Combining enrolment with sync

A typical setup pairs the enrolment with a sync rule so the workflow is:

1. An operator (or another automation) writes a per-user secret to `kv/apps/sample/keys/alice`
2. dotvault, running as `alice`, checks Vault for `users/alice/sample` — the template's fields are absent
3. The copy engine reads `apps/sample/keys/alice`, renders the template, and writes the result to `users/alice/sample`
4. The sync rule picks up the new secret and writes the local file
5. On every subsequent poll (and on `data-write` events on Vault Enterprise), the WatchManager re-evaluates the copy and writes back only if the result has changed

On subsequent daemon starts the enrolment check finds the template's fields already present and skips the interactive part of the wizard, but the WatchManager continues to mirror upstream changes for as long as the daemon is running.
