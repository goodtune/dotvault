# Multi-Dimension Layer Composition

## Overview

The original composition model fixed both the addressable dimensions and their order: `global → os/<os> → group/<g> (sorted) → user/<user>`. This design generalises it: a layer is addressable by **any combination of dimensions** — os, group, device, user — and composes into the document whenever **all** of its specified dimensions match the request. All matching layers are additive; there are no exclusions.

The service configuration declares an **explicit, ordered list** of the dimension combinations it will consider. Each entry defines both which dimensions must match and its position in the merge order. The operator decides precedence by ordering the list — no implicit specificity rules, no surprises. A combination not in the list is never looked up and never served.

## Dimensions

A fixed vocabulary, each mapping to a client-asserted request value:

| Dimension | Source | Notes |
|-----------|--------|-------|
| `os` | `X-Dotvault-OS` | lowercased; mandatory identity |
| `group` | groups resolver applied to the user | multi-valued |
| `device` | `X-Dotvault-Hostname` | lowercased; optional — the client already sends it, so no client change |
| `user` | `X-Dotvault-User` | mandatory identity |

A kind referencing a dimension with no value for the request (e.g. `device` from an older client that sends no hostname) contributes nothing and is skipped. A kind containing `group` expands once per group, sorted, all at that entry's position — a user in two groups receives the additive union, exactly as before.

## Kinds and layer keys

A **kind** is a set of dimensions in **canonical spelling**: dimensions joined with `+` in the fixed order os, group, device, user — `os+group`, never `group+os` (rejected with the canonical spelling named, mirroring the case-sensitivity stance in `ParsePartial`: one combination, one spelling, one key shape). The empty kind is `global`.

Layer keys extend the existing grammar backward-compatibly:

```
key  := "global" | kind "/" value ("/" value)*       (one value per dimension, in kind order)

os/linux                          (existing single-dimension keys unchanged)
os+group/windows/sydney
os+group+user/windows/sydney/gary
```

Values are identity segments (no path separators, no `..`, no control characters); `os` and `device` values must be lowercase because composition lowercases the client's value — an uppercase segment would be stored and never served.

## Configuration

```yaml
composition:
  order: [os, group, device, user, os+group, os+user, group+user, os+group+user]
```

A request matching `os=windows, group=sydney, user=gary` composes layers in exactly that order, skipping any combination with no stored layer. Validation enforces **well-formedness only**: known dimensions, canonical intra-kind spelling, no duplicate dimensions within a kind, no duplicate entries, at least one entry. Ordering *between* entries is deliberately unconstrained — `os` is not required to precede `os+group`, and `global` (an ordinary entry) may appear anywhere or not at all.

## Migration and coexistence

Omitting the `composition` block keeps the original fixed sequence `[global, os, group, user]` — compositions are byte-identical, ETags are stable, and no stored layer needs migrating (the old keys are the single-dimension cases of the new grammar). Declaring a block replaces the default **wholesale**, including `global`: list it if you want it.

The write paths gate on the configured order: the admin layer `PUT` answers `422` and `seed` refuses the publish when a layer's kind is not listed, so dead configuration — a layer that would never be looked up — fails loudly at publish time. Admin `GET`/`DELETE` stay grammar-only so an operator can inspect and remove layers left behind after shrinking the list.

## Surfaces

- `GET /v1/config` reads the device dimension from `X-Dotvault-Hostname` (optional; validated like the other dimensions when present).
- `GET /v1/admin/preview` and `dotvault-config compose` gain a `device` parameter/flag.
- Seed directories mirror the grammar: one directory per kind, one nested level per dimension value (`os+group/windows/sydney.yaml`); a layer file at the wrong depth is an error, never silently skipped.

## Future work

Extra dimensions keyed on configured `remote_config.headers` (e.g. an environment header) — the kind/expansion machinery is dimension-generic, so this is a vocabulary extension; service-side composed-response caching keyed by the full dimension tuple.
