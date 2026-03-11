# litesync-bridge — Design & Implementation Plan

## Overview

CouchDB(Self-hosted LiveSync) ↔ 로컬 파일시스템 양방향 동기화 데몬.
기존 Deno/TypeScript bridge를 Rust로 재작성한다.

## Architecture

```
┌──────────────────────────────────────────────┐
│                litesync-bridge               │
│                                              │
│  ┌──────────┐   Hub    ┌──────────────────┐  │
│  │PeerCouchDB├────┬────┤ PeerStorage      │  │
│  │(per vault)│    │    │ (per vault)      │  │
│  └─────┬─────┘    │    └────────┬─────────┘  │
│        │     group routing      │            │
│  ┌─────▼─────┐          ┌──────▼──────────┐  │
│  │ livesync- │          │  notify/tokio   │  │
│  │ commonlib │          │  fs watcher     │  │
│  └─────┬─────┘          └──────┬──────────┘  │
│        │                       │             │
└────────┼───────────────────────┼─────────────┘
         │                       │
    CouchDB (HTTPS)      Local Filesystem
```

## Crate Structure

```
litesync-bridge/
├── Cargo.toml                  # workspace root + binary
├── src/
│   ├── main.rs                 # CLI entry, config loading
│   ├── config.rs               # Config deserialization
│   ├── hub.rs                  # Peer orchestration, group routing
│   ├── peer/
│   │   ├── mod.rs              # Peer trait
│   │   ├── couchdb.rs          # CouchDB peer (changes feed → dispatch)
│   │   └── storage.rs          # Filesystem peer (watch → dispatch)
│   └── bridge.rs               # Change event types, dispatch logic
│
└── crates/
    └── livesync-commonlib/     # LiveSync protocol implementation
        ├── Cargo.toml
        └── src/
            ├── lib.rs
            ├── couchdb.rs      # CouchDB HTTP client (_changes, CRUD)
            ├── doc.rs          # Document types (NewEntry, PlainEntry, EntryLeaf)
            ├── chunk.rs        # Chunk splitting & reassembly
            ├── crypto.rs       # E2EE (AES-GCM, HKDF, path obfuscation)
            └── path.rs         # Path ↔ Document ID conversion
```

## LiveSync Protocol (from TypeScript analysis)

### Document ID Format

```
path2id_base(path):
  1. path가 "_"로 시작하면 "/" prefix 추가 ("_" → "/_")
  2. obfuscatePassphrase가 있으면:
     - SHA-256(passphrase)를 len(passphrase)번 반복 해싱
     - SHA-256("{hashedPassphrase}:{path}") → hex string을 ID로 사용
  3. 없으면 path 자체가 ID
```

### Document Types

```rust
// 텍스트 파일 (Markdown 등)
PlainEntry {
    _id: String,        // path2id_base(path)
    _rev: String,       // CouchDB revision
    type_: "plain",
    path: String,       // E2EE 시 "/\:" + ciphertext
    ctime: u64,
    mtime: u64,
    size: u64,
    children: Vec<String>,   // chunk document IDs
    eden: HashMap<String, EntryLeaf>,  // incubated chunks (inline)
}

// 바이너리 파일 (이미지 등)
NewEntry {
    // PlainEntry와 동일 구조, type_: "newnote"
}

// Chunk document
EntryLeaf {
    _id: String,        // "h:{hash(content)}"
    type_: "leaf",
    data: String,       // base64-encoded content
}
```

### E2EE

```
Key Derivation:
  1. PBKDF2(passphrase, salt, 310000 iterations, SHA-256) → 256-bit master key
  2. HKDF-Expand(masterKey, random 32-byte salt, SHA-256) → per-chunk key
  3. AES-256-GCM(key, random 12-byte IV, plaintext) → ciphertext

Encrypted document format:
  - path 필드: "/\:" + encrypted({path, mtime, ctime, size, children})
  - chunk data: encrypted(base64 content)

Path Obfuscation (별도):
  - passphrase를 SHA-256으로 len(passphrase)번 반복 해싱
  - 각 path를 SHA-256("{hashed}:{path}")으로 변환 → document ID에 사용
```

### Chunk Splitting

```
splitPieces2V2():
  - 텍스트: "\n" 기준으로 분할, 코드 블록(```) 내부는 유지
  - 바이너리: "\0" 또는 "\n" 기준으로 분할
  - 최소 chunk 크기: 10^(step-1), step = floor(fileSize / 12.5) 기반 동적 계산
  - Content addressing: chunk ID = "h:{xxhash(content)}"
  - 동일 content → 동일 ID → 자동 중복 제거
```

### Changes Feed

```
PouchDB .changes({
    since: last_seq,     // 마지막 처리한 시퀀스 (string | number)
    include_docs: true,
    selector: { type: { $ne: "leaf" } },  // chunk 제외, 문서만
    live: true,          // long-polling / continuous
})

→ 각 change에서:
  1. doc.type이 "plain" 또는 "newnote"인지 확인
  2. E2EE 시 path 필드 복호화 → 실제 파일 경로 추출
  3. children[]의 chunk ID로 chunk document fetch
  4. chunk 데이터 복호화 + 결합 → 원본 파일 복원
  5. this.since = change.seq (★ 기존 bridge 버그: 이걸 안 했음)
```

### Write-Back (File → CouchDB)

```
1. 파일 읽기 → bytes
2. chunk 분할 (splitPieces2V2)
3. 각 chunk를 content-hash → chunk ID 생성
4. E2EE 시 각 chunk 암호화
5. chunk documents를 CouchDB에 PUT (이미 존재하면 skip)
6. parent document 생성/업데이트 (path, children[], mtime 등)
7. E2EE 시 parent의 path 필드도 암호화
8. parent document를 CouchDB에 PUT
```

## Implementation Phases

### Phase 1: livesync-commonlib core (Read-only)

CouchDB에서 데이터를 읽어서 복호화할 수 있는 수준까지.

```
1.1  couchdb.rs  — HTTP client
     - CouchDB 인증 (Basic Auth)
     - GET/PUT/DELETE document
     - _changes feed (long-polling)
     - _bulk_get for batch chunk fetching

1.2  path.rs — Path ↔ ID conversion
     - path2id / id2path
     - path obfuscation (SHA-256 chain)

1.3  doc.rs — Document types
     - PlainEntry, NewEntry, EntryLeaf serde models
     - Milestone document parsing

1.4  crypto.rs — E2EE decryption
     - PBKDF2 key derivation (310k iterations)
     - HKDF-Expand per-chunk key
     - AES-256-GCM decryption
     - Path field decryption

1.5  chunk.rs — Chunk reassembly (read direction)
     - Fetch children chunks by ID
     - Decode base64, decrypt, concatenate
     - Eden (inline) chunk handling
```

**Milestone: CouchDB vault를 로컬 파일로 dump할 수 있음**

### Phase 2: livesync-commonlib write path

```
2.1  chunk.rs — Chunk splitting
     - Text splitting (newline-based, code block aware)
     - Binary splitting
     - Content-addressed chunk ID generation (xxhash)

2.2  crypto.rs — E2EE encryption
     - AES-256-GCM encryption
     - Path field encryption
     - Random IV/salt generation

2.3  couchdb.rs — Write operations
     - PUT chunk documents (conflict-safe, skip existing)
     - PUT/UPDATE parent documents with _rev handling
     - DELETE with proper _rev
```

**Milestone: 로컬 파일을 CouchDB에 업로드할 수 있음**

### Phase 3: Bridge daemon

```
3.1  config.rs — Config file parsing
     - dat/config.json 호환 (기존 설정 재사용)
     - 환경변수 override

3.2  peer/couchdb.rs — CouchDB peer
     - _changes feed 소비 (continuous/long-polling)
     - since 시퀀스 추적 + 영속화 (★ 기존 버그 수정)
     - 변경 이벤트를 hub에 dispatch

3.3  peer/storage.rs — Filesystem peer
     - notify crate로 파일 감시
     - 오프라인 변경 스캔 (startup reconciliation)
     - stat 추적 (mtime + size)으로 변경 감지

3.4  hub.rs — Peer orchestration
     - Group-based routing
     - 양방향 reconciliation (★ 기존 부재 수정)
     - Deduplication (content hash 기반)

3.5  bridge.rs — Change event types
     - Created / Modified / Deleted events
     - 삭제 전파 시 _rev retry 로직 (★ 기존 부재 수정)
```

**Milestone: 양방향 실시간 동기화 데몬 동작**

### Phase 4: Production readiness

```
4.1  Graceful shutdown (SIGTERM/SIGINT)
4.2  Structured logging (tracing)
4.3  Health check endpoint (optional HTTP)
4.4  Systemd service file
4.5  Config validation & startup diagnostics
4.6  deno compile 대비 cross-compilation (x86_64, aarch64)
```

## Key Differences from Original Bridge

| 문제 | 기존 (Deno) | 신규 (Rust) |
|------|------------|-------------|
| since 시퀀스 추적 | 버그 — V2에서 갱신 안 함 | 매 change마다 갱신 + 파일에 영속화 |
| 양방향 reconciliation | 로컬→CouchDB만 | startup 시 양방향 diff |
| 삭제 전파 | _rev 불일치 시 실패, 재시도 없음 | _rev fetch → retry 로직 |
| 파일 이동 | 미지원 (race condition) | create+delete를 atomic batch로 처리 |
| 런타임 | Deno 2.x 필요 | 단일 바이너리, 런타임 불필요 |
| 바이너리 크기 | ~80-100MB (deno compile) | ~10-15MB (static linked) |

## Config Format (backward compatible)

```jsonc
{
  "peers": [
    {
      "type": "couchdb",
      "name": "personal-remote",
      "group": "personal",
      "database": "obsidian-personal",
      "username": "obsidian",
      "password": "***",
      "url": "https://couch.lab16.app",
      "passphrase": "***",
      "obfuscatePassphrase": "***",
      "baseDir": ""
    },
    {
      "type": "storage",
      "name": "personal-local",
      "group": "personal",
      "baseDir": "/root/obsidian-vaults/personal/",
      "scanOfflineChanges": true
    }
  ]
}
```

## Dependencies

### livesync-commonlib

| Crate | Purpose |
|-------|---------|
| reqwest (rustls) | CouchDB HTTP client |
| serde + serde_json | Document serialization |
| aes-gcm | AES-256-GCM encryption |
| hkdf + sha2 | Key derivation |
| xxhash-rust | Content-addressed chunk IDs |
| flate2 | Compression |
| base64 | Chunk data encoding |
| thiserror | Error types |

### litesync-bridge (binary)

| Crate | Purpose |
|-------|---------|
| tokio | Async runtime |
| notify | Filesystem watching |
| clap | CLI argument parsing |
| tracing | Structured logging |
| anyhow | Error handling |
