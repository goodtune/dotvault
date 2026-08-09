# Disposable test fixture keypair — do not reuse

`dotvault_test_ed25519` / `authorized.pub` is a throwaway ed25519 keypair generated solely for `test/integration/sshfwd_test.go`. It authenticates to nothing except the two throwaway sshd containers started by the `sshfwd` docker-compose profile (`docker compose --profile sshfwd up -d` — see `docker-compose.yaml`), which run only on `127.0.0.1` for the lifetime of a local test run or CI job.

It is committed deliberately, not by mistake: the containers read the public half at startup via `PUBLIC_KEY_FILE`, so the key has to exist before `docker compose up` runs, and generating it at test time would mean restarting the containers from inside the suite — trading a documentation problem for a flakiness problem in the one suite where flakiness costs the most. Committing a static keypair is what lets the containers and the tests agree on a credential with no runtime coordination between them.

It grants access to nothing else, is not a secret in any sense that matters (its blast radius is a container nobody exposes off loopback and that this repository throws away after every test run), and must never be reused for anything beyond this suite — SSH host access, a service account, a CI secret, or any other purpose.
