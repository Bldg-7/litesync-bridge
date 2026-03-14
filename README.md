# litesync-bridge

Bidirectional sync daemon between [CouchDB](https://couchdb.apache.org/) ([Self-hosted LiveSync](https://github.com/vrtmrz/obsidian-livesync)) and a local filesystem. Written in Rust as a drop-in replacement for the original Deno/TypeScript bridge.

## Features

- **Bidirectional sync** — CouchDB changes feed (longpoll) + filesystem watcher (notify)
- **Full LiveSync protocol** — E2EE (V2 HKDF), path obfuscation, chunk splitting (V2/V3 Rabin-Karp), eden optimization
- **Startup reconciliation** — Detects offline changes on both sides and resolves conflicts (mtime LWW)
- **Multi-vault** — Hub routes changes between peer groups (e.g. personal + work vaults)
- **Single binary** — Static-linked (~10 MB), no runtime dependencies
- **Graceful shutdown** — SIGTERM/SIGINT with state persistence (since sequence, stat cache)

## Architecture

```
┌──────────────────────────────────────────────┐
│                litesync-bridge               │
│                                              │
│  ┌──────────┐   Hub    ┌──────────────────┐  │
│  │CouchDBPeer├────┬────┤ StoragePeer      │  │
│  │(per vault)│    │    │ (per vault)      │  │
│  └─────┬─────┘    │    └────────┬─────────┘  │
│        │     group routing      │            │
│  ┌─────▼─────┐          ┌──────▼──────────┐  │
│  │ litesync- │          │  notify/tokio   │  │
│  │ commonlib │          │  fs watcher     │  │
│  └─────┬─────┘          └──────┬──────────┘  │
│        │                       │             │
└────────┼───────────────────────┼─────────────┘
         │                       │
    CouchDB (HTTPS)      Local Filesystem
```

## Quick Start

### Install from source

```bash
git clone https://github.com/Bldg-7/litesync-bridge.git
cd litesync-bridge
cargo build --release
cp target/release/litesync-bridge /usr/local/bin/
```

### Configure

Create `dat/config.json` (compatible with the original Deno bridge format):

```json
{
  "peers": [
    {
      "type": "couchdb",
      "name": "vault-remote",
      "group": "vault",
      "database": "obsidian-livesync",
      "username": "admin",
      "password": "password",
      "url": "https://couch.example.com",
      "passphrase": "your-e2ee-passphrase",
      "obfuscatePassphrase": "your-obfuscation-passphrase",
      "baseDir": ""
    },
    {
      "type": "storage",
      "name": "vault-local",
      "group": "vault",
      "baseDir": "/path/to/vault"
    }
  ]
}
```

Peers in the same `group` are synced bidirectionally. You can define multiple groups for multiple vaults.

### Run

```bash
litesync-bridge --config dat/config.json
```

Options:

| Flag | Description |
|------|-------------|
| `--config <path>` | Config file path (default: `dat/config.json`) |
| `--reset` | Clear since sequences and reconcile from scratch |
| `--log-json` | Structured JSON log output |

### systemd

```bash
cp deploy/litesync-bridge.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now litesync-bridge
```

## Config Reference

### CouchDB Peer

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Unique peer identifier |
| `group` | yes | Sync group (must match a Storage peer) |
| `database` | yes | CouchDB database name |
| `username` | yes | CouchDB username |
| `password` | yes | CouchDB password |
| `url` | yes | CouchDB URL (`https://...`) |
| `passphrase` | no | E2EE passphrase (enables end-to-end encryption) |
| `obfuscatePassphrase` | no | Path obfuscation passphrase |
| `baseDir` | no | Base directory prefix for CouchDB paths |

### Storage Peer

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Unique peer identifier |
| `group` | yes | Sync group (must match a CouchDB peer) |
| `baseDir` | yes | Local filesystem path to sync |

## Cross-compile

```bash
# x86_64 static (musl)
make release-musl

# aarch64 static (musl)
make release-aarch64
```

Requires the corresponding musl target: `rustup target add x86_64-unknown-linux-musl`

## Testing

```bash
# Unit + integration tests
cargo test --workspace

# CouchDB integration tests (requires Docker)
docker run -d --name couchdb-test -p 5984:5984 \
  -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=password \
  couchdb:3
cargo test --workspace -- --ignored
```

## Compatibility

- **Obsidian LiveSync** v0.25.x (Self-hosted LiveSync plugin)
- **CouchDB** 3.x
- **Encryption**: V2 HKDF only (V1 legacy explicitly rejected with migration guidance)
- **Hash algorithms**: xxhash64 (default), xxhash32 (legacy), sha1, mixed-purejs
- **Chunk splitting**: V2 delimiter-based, V3 Rabin-Karp

## License

MIT
