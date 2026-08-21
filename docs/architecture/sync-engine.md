# Sync engine, handlers, templates

> Carved from CLAUDE.md. Per-rule sync logic, the state store, format handlers (including `delete_nulls` tombstones), and template functions. User-facing: `docs/configuration/sync-rules.md`, `docs/configuration/templates.md`.

## Sync Engine

Hybrid event-driven + polling model (`internal/sync/`):

- **Enterprise Vault:** subscribes to `kv-v2/data-write` events via WebSocket (Events API), filters by user prefix, syncs affected rule immediately
- **Community Vault:** poll-only at configured interval
- **Graceful degradation:** if WebSocket fails, falls back to polling with exponential backoff (1s-5m)

Per-rule sync logic:
1. Read secret from Vault at `{kv_mount}/data/{user_prefix}{username}/{vault_key}` — *skipped entirely for a keyless rule* (no `vault_key`), which proceeds with an empty data context
2. Skip only if vault version unchanged AND the rule's render-affecting definition is unchanged AND file checksum unchanged. The rule fingerprint (`ruleRenderHash`: vault key + target path/format/template/merge, length-prefixed) is stored in state and is what makes a template edit re-apply on an otherwise-unchanged secret — without it, editing only `target.template` would skip forever because neither the secret version nor the on-disk file moved. Empty `rule_hash` in state written by an older version forces a one-time reconciling re-sync on upgrade. A keyless rule has no secret version, so for it the fingerprint and file checksum alone carry the skip decision (a never-synced rule's empty stored `rule_hash` can't match the computed one, forcing the first sync).
3. Render template (if present) with Vault data map as dot context (empty for a keyless rule; `{{ username }}` still resolves)
4. Parse rendered output through handler to get incoming structured data
5. Read existing file via handler (missing file is empty state, not error; missing parent dir created at 0755)
6. Merge incoming into existing via handler
7. Write atomically (temp file + rename)
8. Update state (version, timestamp, checksum, rule hash)

Per-rule isolation: one rule failing does not block others.

### State Store

Persists to `{cache_dir}/state.json`. Per-rule: vault version, last synced timestamp, SHA-256 file checksum, and `rule_hash` (the render-affecting rule fingerprint that gates re-sync on a template edit). Atomic writes via temp file + rename.

## File Format Handlers

All handlers implement the `FileHandler` interface (Read, Merge, Write). Handlers that support templates also implement the `Parser` interface. Factory: `handlers.HandlerWithOptions(format, handlers.Options{...})`, which the sync engine calls; `handlers.HandlerFor(format)` is the zero-option wrapper. `Merge` may mutate **both** arguments — it builds the result by modifying `existing` in place, and a delete-nulls handler also strips tombstones out of `incoming` — so a caller must parse both fresh per rule, as the engine does.

| Format | Library | Merge Behaviour |
|--------|---------|-----------------|
| YAML | `gopkg.in/yaml.v3` (Node-based) | Deep merge mapping nodes; preserves existing keys not in incoming |
| JSON | `encoding/json` | Recursive map merge; arrays replaced wholesale |
| INI | `gopkg.in/ini.v1` | Section + key merge; supports flat files (default section) |
| TOML | Custom parser (no external dep) | Recursive merge like JSON; supports tables, inline tables, dotted keys |
| Text | Plain string | Full replacement (no merge) — for private keys, certificates |
| Netrc | `github.com/jdx/go-netrc` | Per-entry merge by machine name; default entry skipped |
| ssh_config | Custom parser (no external dep) | Surgical directive-level merge within each Host/Match section; comments and unmanaged directives preserved verbatim. Template-only (no raw-data path). Repeatable keywords (forwards, `IdentityFile`, `SetEnv`, …) merge by a discriminator drawn from the first argument, so the discriminator *is* the directive's identity: changing it renders a new line (old one orphaned), not a rewrite — a deliberate coexistence trade-off, documented in `docs/configuration/sync-rules.md` |

The `merge` field exists in rule config but is not dispatched on. Each handler always uses its native merge strategy, which is the only sensible strategy for that format.

**Field nullification (`target.delete_nulls`).** The merge is additive by construction, so a rule can add and update keys but never retire one: a secret published into a file and later moved to a dynamic source stays on disk whether the rule keeps writing (the merge preserves it) or is deleted (the file stops being managed). With `delete_nulls`, a null in the *incoming* rendered document is a tombstone — the key is removed from the target instead of written — the equivalent of `jq`'s `del(.key)`. Deleting an absent key is a no-op, so a tombstone is safe to leave in a template permanently and stops changing the file once the key is gone. The flag reaches the handler via `handlers.Options`/`HandlerWithOptions` (`HandlerFor` stays the zero-value default) and is carried on `JSONHandler`/`YAMLHandler` as a struct field; it is also mixed into `ruleRenderHash`, so toggling it re-applies against an otherwise-unchanged secret. **It is opt-in per rule, and that is load-bearing:** in YAML `password: {{ .password }}` over an empty value renders `password:`, which parses as a null — always-on deletion would silently delete live credentials. All three YAML null spellings (`null`, `~`, bare `key:`) are tombstones. Two gates reject the flag on null-less formats: `config.validateRule` at load time and `HandlerWithOptions` at construction, the latter so a caller building a handler by another route can't quietly get additive-only merges when it asked for deletions. Both the JSON and YAML implementations must *prune* tombstones from any src subtree adopted wholesale rather than merged key-by-key (`pruneNullsJSON` / `pruneNullNodes`) — the `!exists` and replace branches would otherwise write out the very null the rule asked to delete.

Tombstones reach **mapping keys only**. Neither handler descends into arrays/sequences, because the merge replaces those wholesale and there is nothing inside one to delete; the two were briefly inconsistent here and `TestDeleteNullsTreatsArraysAsOpaque` pins them together. Three further properties exist because a deletion that silently doesn't happen is worse than no feature at all: **every** duplicate key is removed, not just the first (yaml.v3 permits duplicates and consumers read the last one); the YAML merge **refuses outright** — erroring the rule rather than writing — when the *existing* document uses an anchor, alias, or merge key and the incoming document carries a tombstone (`unsafeForDeletion`/`hasTombstone`), since a key inherited via `<<: *base` isn't written literally and removing an anchored pair strands aliases; and on Windows `TargetDeleteNulls` is read with `readRegDWORDStrict`, so a mistyped GPO value fails startup instead of silently reading as disabled. The refusal is gated on a tombstone actually being present, so a delete_nulls rule that renders no null this pass still works against an aliased file. Removal for the formats with no null (`ini`, `toml`, `text`, `netrc`, `ssh_config`) is an open design question, not a supported gesture.

All writes are atomic (temp file with target permissions + rename). Permissions: all managed files use 0600.

## Template Processing

`internal/tmpl/` wraps `text/template` with custom functions:

- `env(key)` — environment variable lookup
- `base64encode(s)` / `base64decode(s)` — credential encoding
- `default(fallback, val)` — Sprig convention (fallback first)
- `quote(s)` — shell-safe single quoting
- `username` — the OS account dotvault runs under, i.e. the same `paths.Username()` identity the `kv/users/<username>/…` layout is built from (`DOMAIN\` stripped). It is a function rather than a dot-context field so it is available regardless of the secret's contents and cannot be shadowed by a secret field named `user`. Bound by `tmpl.RenderWithUsername` (the sync engine passes `e.username`); plain `tmpl.Render` leaves it bound to `""`. This is the seam that lets a rule template build per-user paths like `/home/{{ username }}/.ssh/dotvault.sock` without the username being stored in Vault.

Templates receive the Vault KV data map as dot context. The rendered output is parsed by the target format's handler to produce structured incoming data. The dot context is *only* the secret's fields — there is no implicit `.user`; per-user values that aren't secret data come from the `username` function instead.

