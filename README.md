# Genesis client installer

Install or update the `genesis` CLI on Linux or macOS:

```bash
curl -fsSL https://genesis.99point.co/install | bash
```

`install.sh` pins the immutable commit of `genesis.mjs` and
`agent-auth-setup.sh` it was published with and verifies their SHA-256
before installing under `~/.local/share/genesis`. `genesis --update`
re-runs the same line. Source of truth: `packages/agent-auth/` in
`99point/system-99` (staging pushes republish this repository).
