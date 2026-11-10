# Genesis client installer

Install or update the `genesis` CLI on Linux or macOS:

```bash
curl -fsSL https://genesis.99point.co/install | bash
```

`install.sh` pins the immutable commit of `genesis.mjs` and
`agent-auth-setup.sh` it was published with and verifies their SHA-256
before installing under `~/.local/share/genesis`. `genesis --update`
uses this publication. There is one CLI for both Prod and Staging; the
gateway selected inside it does not choose a different package. Updates
preserve the selected gateway, saved logins and configured clients.

Source of truth: `packages/genesis/` in `99point/system-99`. The owner
publishes the CLI from `agent-auth/native-release`. Gateway releases do
not publish another CLI.
