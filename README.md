# Zeplicator Air

Air-gapped ZFS replication over HTTPS with mutual TLS. No SSH between nodes — the `zep-air-serve` TLS server is the sole communication channel. Pure C, ~3500 LOC.

## Synopsis

```
master ──push──▶ [zep-air-serve] ◀──pull── client
```

Each node runs `zep-air cron --daemon`. The server (the *only* network-facing component) tells each node what to do: master gets a list of labels due to push, clients get filesystems to poll for new snapshots. Push pipeline: `zfs send → zstd → chunk → SHA256 → HTTPS PUT`. Pull pipeline: `HTTPS GET → verify → reassemble → zstd -d → zfs recv`. The server parses every received stream with `zstream dump` and is the authoritative source of the GUID chain — fast SQLite lookups replace slow `zfs list` on pools with thousands of snapshots.

### Components

| Binary | Role |
|--------|------|
| `zep-air-serve` | HTTPS server (TLS), REST API, cluster state, chain tracking |
| `zep-air` | Node agent — push, pull, snap, rotate, cron daemon |
| `zep-air-admin` | Remote admin tool — cluster management, node registration |

### Security

| Layer | Mechanism |
|-------|-----------|
| Transport | TLS 1.3 with GnuTLS |
| Authentication | Mutual TLS — all nodes and admins present client certificates |
| Authorization | Role-based (admin/master/client), enforced per-endpoint via cert fingerprint |
| Encryption | `zfs send -w` (raw) + TLS in transit; `zstd` compression in transit |
| Integrity | SHA256 per chunk, verified on pull; server re-verifies via `zstream dump` |
| Immutability | Snapshot chain anchored by common ground; protected GUIDs never purged |

## Quick Start

### 1. Build and install

```sh
# Dependencies (Debian/Ubuntu)
sudo apt install gcc make libcurl4-openssl-dev libssl-dev libsqlite3-dev \
  libcjson-dev libmicrohttpd-dev libzstd-dev libgnutls28-dev zfsutils-linux

make
sudo make install
```

### 2. Create PKI

Two helper scripts in `pki/` — `mk-ca.sh` creates the CA, server, and admin certs. `mk-node.sh` creates node certs.

```sh
# Create CA, server cert (for zep-air-serve), and admin cert
./pki/mk-ca.sh "/C=IT/O=CompEd/CN=Zep-Air testing" 3650 master.zep.lan

# Create node certs (repeats for each node)
./pki/mk-node.sh za-master
./pki/mk-node.sh za-client-1
./pki/mk-node.sh za-client-2
```

Each invocation produces a combined `.pem` file (cert + key concatenated) — copy this single file to the node. No separate `.crt` / `.key` logistics.

**Password-protected keys (recommended for admins):**

```sh
# Add -p to encrypt private keys with AES-256 (prompts for password)
./pki/mk-ca.sh -p
./pki/mk-node.sh za-master -p

# All binaries accept -P / --password to decrypt at startup:
zep-air-serve --cert server.pem --ca ca.crt -P 'thepassword'
zep-air-admin --cert admin.pem --ca ca.crt -P 'thepassword'
zep-air config set key_password 'thepassword'   # node agent reads from config
```

**What you get:**
| File | Contents | Distribute to |
|------|----------|---------------|
| `ca.crt` | CA certificate (public) | All nodes |
| `server.pem` | Server cert + key | `zep-air-serve` host |
| `admin.pem` | Admin cert + key | Admin workstation |
| `<CN>.pem` | Node cert + key | That specific node |

### 3. Server setup and start

```sh
# One-time: register CA, server cert, and admin cert
zep-air-serve --setup \
  --cert pki/server.pem --ca pki/ca.crt \
  --admin-cert pki/admin.pem

# Start the server (with encrypted key)
zep-air-serve --port 8443 \
  --cert pki/server.pem --ca pki/ca.crt \
  -P 'key-password' &
```

### 4. Define a cluster

```sh
cat > cluster.json << 'EOF'
{
  "name": "prod",
  "pools": {
    "tank-prod": {
      "data":   {"labels": {"min": 60,  "hour": 24,  "day": 30}},
      "home":   {"labels": {"min": 120, "hour": 12,  "day": 7}}
    }
  }
}
EOF

zep-air-admin \
  --server https://master.zep.lan:8443 \
  --cert pki/admin.pem --ca pki/ca.crt \
  cluster set --file cluster.json
```

### 5. Register nodes

```sh
# Master — maps cluster pool/fs to local pool/fs
zep-air-admin \
  --server https://master.zep.lan:8443 \
  --cert pki/admin.pem --ca pki/ca.crt \
  join --role master --cluster prod --node za-master \
  --cert pki/za-master.crt \
  --map "tank-prod/data:rpool/master, tank-prod/home:rpool/master-home"

# Client — maps to its own local pool/fs, overrides retention
zep-air-admin \
  --server https://master.zep.lan:8443 \
  --cert pki/admin.pem --ca pki/ca.crt \
  join --role client --cluster prod --node za-client-1 \
  --cert pki/za-client-1.crt \
  --map "tank-prod/data:vault/data(day:90,month:12), tank-prod/home:vault/home"
```

### 6. Configure nodes and run

Each node has a local SQLite database (`zep-air.db` in the working directory, or `--db PATH`). Config is stored there, along with push/pull history. No central config — the server is only for sync, not configuration.

**Master (`za-master`):**
```sh
zep-air config set node_name za-master
zep-air config set server_url https://master.zep.lan:8443
zep-air config set cert_path pki/za-master.pem
zep-air config set ca_path   pki/ca.crt
zep-air config set cluster prod
# zep-air config set key_password 'password'  # if key is encrypted
zep-air config set mapping "tank-prod/data:rpool/master, tank-prod/home:rpool/master-home"

zep-air cron --daemon
```

**Client (`za-client-1`):**
```sh
zep-air config set node_name za-client-1
zep-air config set server_url https://master.zep.lan:8443
zep-air config set cert_path pki/za-client-1.pem
zep-air config set ca_path   pki/ca.crt
zep-air config set cluster prod
# zep-air config set key_password 'password'  # if key is encrypted
zep-air config set mapping "tank-prod/data:vault/data(day:90), tank-prod/home:vault/home"

zep-air cron --daemon
```

## CLI Reference

### `zep-air`

```
zep-air <command> [options]

Commands:
  snap     Create local snapshots (no push)
  cron     Query server, execute due push/pull tasks
  rotate   Purge snapshots beyond retention (safe — skips protected GUIDs)
  push     Snapshot + compress + chunk + upload to server
  pull     Discover + download + verify + zfs recv from server
  config   Manage local configuration (SQLite)
  status   Show push/pull history
```

**`push`**
```
zep-air push --label hourly                              # all mapped filesystems
zep-air push --label hourly tank-prod/data               # cluster fs name via mapping
zep-air push -f rpool/master --label hourly              # direct local fs
```

**`pull`**
```
zep-air pull -d za-master                                # all mapped filesystems
zep-air pull -d za-master tank-prod/data                 # specific cluster fs
zep-air pull -f vault/data -d za-master                  # direct local fs
```

**`snap`**
```
zep-air snap --label hourly                              # all mapped (cluster-aware naming)
zep-air snap --label hourly tank-prod/data               # specific
zep-air snap -f rpool/master --label hourly              # direct

# Snapshot name: <pool/fs>@<cluster>-<label>-<timestamp>
# Example: rpool/master@prod-min-2026-05-06-153045
```

**`cron`**
```
zep-air cron                           # run once
zep-air cron --daemon                  # loop forever
zep-air cron --daemon --interval 30    # every 30 seconds
```

**`rotate`**
```
zep-air rotate                         # all mapped filesystems
zep-air rotate tank-prod/data          # specific cluster fs
zep-air rotate -f rpool/master         # direct local fs
```

**`config`**

Stores values in a local SQLite database (`./zep-air.db` by default, override with `--db`).

```
zep-air config set key value
zep-air config get key
zep-air config list
```

**Config keys:**
| Key | Description |
|-----|-------------|
| `node_name` | This node's identity (must match cert CN) |
| `server_url` | `zep-air-serve` URL (e.g. `https://srv:8443`) |
| `cert_path` | Path to this node's TLS client cert (`.pem` or `.crt`) |
| `key_path` | Path to private key (defaults to cert_path for combined `.pem`) |
| `ca_path` | Path to CA certificate |
| `key_password` | Password for encrypted private key |
| `cluster` | Cluster name to operate on |
| `mapping` | Pool/fs translation: `cluster_fs:local_fs(label:ret,...),...` |
| `chunk_size` | Max blob size in bytes (default 10 MB) |
| `send_options` | Extra `zfs send` flags (`-w`, `-p`, `-R`) |
| `recv_options` | Extra `zfs recv` flags |
| `send_all_snap` | `1` = use `-I` (all snapshots), `0` = `-i` (single incremental) |
| `pipe_zip_cmd` | Compression command (default: `zstd -c`, set `""` to disable) |
| `pipe_unzip_cmd` | Decompression command (default: `zstd -d`) |
| `pipe_send_buf_cmd` | Buffer command before compression (e.g. `mbuffer -q -m 512M`) |
| `pipe_recv_buf_cmd` | Buffer command after decompression |
| `pipe_allow` | Comma-separated allowed command prefixes (default: `zfs`). Supports negation (`zfs !destroy`) and prefix matching (`zfs snap` matches `zfs snapshot`). Empty string disables pipe entirely. |

### `zep-air-serve`

```
zep-air-serve [options]

Options:
  --setup, -S           One-time: store CA, server, and admin certs in DB
  --port, -p PORT       Listen port (default 8443)
  --storage, -s DIR     Blob storage directory (default /var/lib/zep-air)
  --cert, -c FILE       Server TLS certificate (PEM, combined cert+key)
  --key, -k FILE        Server private key (defaults to --cert for .pem)
  --ca, -a FILE         CA certificate for client auth (PEM)
  --admin-cert FILE     Admin client cert for --setup mode (PEM)
  --password, -P PASS   Password for encrypted private key
  --db, -D FILE         SQLite database path
  --verbose, -v         Verbose logging
```

### `zep-air-admin`

```
zep-air-admin [global options] <command> [args]

Global:
  --server, -s URL      Server URL
  --cert, -c FILE       Admin client certificate (PEM, combined cert+key)
  --key, -k FILE        Private key (defaults to --cert for .pem)
  --ca, -C FILE         CA certificate
  --password, -P PASS   Password for encrypted private key

Commands:
  cluster set --file JSON   Define a cluster
  cluster get [name]        List clusters or get one
  cluster delete <name>     Remove a cluster
  join --role ROLE --node NAME --cert FILE
        [--cluster NAME] [--map MAPPINGS]
  list-nodes                List registered nodes
  remove-node <CN>          Remove a node
  config list               List server config
  config get KEY            Get server config value
  config set KEY VALUE      Set server config value
  config rm KEY             Remove server config key
  suspend [--master|--clients|--node CN]  Pause replication
  resume  [--master|--clients|--node CN]  Resume replication
  promote --node CN         Promote client to master
  rollback --snap NAME      Cluster-wide rollback to snapshot
  snap create --name NAME   Manual snapshot (no rotation)
  snap destroy --name NAME  Remove manual snapshot
  pipe [--compress] [--buffer] [--chunk N] --node CN [--progress] [--] <command...>  Run command on remote node via WebSocket, stream stdout+stderr
```

### `pipe` — Run commands on remote nodes (WebSocket)

Runs a command on a remote node, streaming `stdin`/`stdout`/`stderr` in real time through the server via a WebSocket bridge. The server checks the command against `pipe_allow` before forwarding. No disk storage — pure pipe-through. The remote exit code is returned as the admin's own exit code.

```
zep-air-admin pipe [--compress] [--buffer] [--chunk N] --node <CN> [--progress] [--] <command...>
```

| Option | Description |
|--------|-------------|
| `--node CN` | Target node (required) |
| `--compress` | Apply `pipe_zip_cmd`/`pipe_unzip_cmd` compression pipeline (future) |
| `--buffer` | Apply `pipe_send_buf_cmd`/`pipe_recv_buf_cmd` buffering pipeline (future) |
| `--chunk N` | Stdin read size in bytes (default: 16380, max one TLS record) |
| `--progress` | Print transfer statistics on stderr |
| `--" --"` | Optional separator between options and command |
| `<command...>` | Command and arguments to execute on the remote node |

**Send direction (admin stdin → node → admin stdout+stderr):**

Unlike the old architecture, there is no `--recv` flag — the direction is always full-duplex. Admin stdin feeds the remote process, remote stdout/stderr stream back to admin's stdout/stderr.

```sh
# Stream zfs send output to local file
zep-air-admin pipe --node za-master zfs send -R rpool/data > backup.zfs

# Pipe stream directly into zfs recv
zep-air-admin pipe --node za-master zfs send -R rpool/data | zfs recv -F -u vault/data

# dd through pipe (requires pipe_allow update)
zep-air-admin pipe --node za-client-1 dd if=/dev/zero bs=1M count=100 > random.bin

# Feed data into remote recv
zep-air-admin pipe --node za-client-1 zfs recv -F -u vault/data < backup.zfs

# Execute remote command, check exit code
zep-air-admin pipe --node bench -- bash -c "exit 42"; echo $?  # prints 42
```

**`pipe_allow` server config (enforced by the server before forwarding):**

```
# Default — only zfs commands
zep-air-admin config set pipe_allow zfs

# Allow zfs + dd + bash
zep-air-admin config set pipe_allow "zfs,dd,bash"

# Allow zfs but deny dangerous subcommands
zep-air-admin config set pipe_allow "zfs !destroy,zfs !promote,zpool !destroy"

# Allow zfs snapshot subcommands (prefix match)
zep-air-admin config set pipe_allow "zfs snap,zfs send,dd"

# Disable pipe entirely
zep-air-admin config set pipe_allow ""
```

**`pipe_allow` syntax:**

| Pattern | Description |
|---------|-------------|
| `zfs` | Allow any `zfs` command |
| `zfs list` | Allow only `zfs list` (and sub-args) |
| `zfs !destroy` | Allow `zfs` but deny `zfs destroy` |
| `zfs !destroy !promote` | Deny multiple subcommands |
| `zfs snap` | Prefix match: allows `zfs snapshot`, `zfs snap-anything` |
| `zfs sna` | Prefix match: allows `zfs snapshot` (partial token) |

Entries are comma-separated, evaluated left-to-right, first match wins. Negated entries deny immediately (no fallthrough to later entries).

**Protocol (WebSocket frames):**

| Opcode | Direction | Payload |
|--------|-----------|---------|
| `0x01` (TEXT) | node → admin | stderr text |
| `0x02` (BIN) | bidirectional | stdin/stdout data |
| `0x03` (EOF) | node → admin | stdin/stdout closed |
| `0x04` (EXIT) | node → admin | 1-byte exit code |
| `0x08` (CLOSE) | bidirectional | connection close |

**Architecture:**

```
Admin ──WS──▶ [zep-air-serve] ◀──WS── node
          stdin→          ←stdout+stderr+exit
```

The server bridges both WebSocket connections directly. No polling, no disk storage, no chunked REST API. The server validates the command against `pipe_allow` before forwarding to the node.

The node executes `execvp()` directly — no shell (`/bin/sh`), no command injection risk. Arguments are tokenized with single/double quote support matching shell behavior.

## REST API

### Data routes (pushed by nodes)

```
PUT  /v1/nodes/<node>/snapshots/<prefix>/meta
PUT  /v1/nodes/<node>/snapshots/<prefix>/blobs/<N>
GET  /v1/nodes/<node>/snapshots
GET  /v1/nodes/<node>/snapshots/<prefix>/meta.json
GET  /v1/nodes/<node>/snapshots/<prefix>/blobs/<N>
```

### Admin routes (admin cert required)

```
POST   /v1/admin/clusters              Create cluster definition
GET    /v1/admin/clusters              List clusters
GET    /v1/admin/clusters/<name>       Get cluster
DELETE /v1/admin/clusters/<name>       Remove cluster
POST   /v1/admin/nodes                 Register master/client
GET    /v1/admin/nodes                 List nodes
DELETE /v1/admin/nodes/<cn>            Remove node
GET    /v1/admin/config                List server config
GET    /v1/admin/config/<key>          Get config value
POST   /v1/admin/config/<key>          Set config value
DELETE /v1/admin/config/<key>          Remove config key
POST   /v1/admin/suspend[/master|clients|<cn>]  Pause replication
POST   /v1/admin/resume[/master|clients|<cn>]   Resume replication
POST   /v1/admin/promote/<cn>          Promote client to master
POST   /v1/admin/rollback/<snap>       Cluster rollback target
POST   /v1/admin/snap/<name>           Manual snapshot (no rotation)
POST   /v1/admin/unsnap/<name>         Remove manual snapshot
```

### Cron routes

```
GET  /v1/cron/sync                  Returns due tasks per node
POST /v1/cron/ack                   Report latest pulled GUID
GET  /v1/cron/protected?<cluster>   GUIDs unsafe to delete
```

### Health

```
GET  /health                        Always 200 (no auth)
```

### WebSocket endpoints

```
GET  /v1/ws/node?cn=<CN>            Node persistent connection (upgrade to WS)
GET  /v1/ws/pipe?node=<CN>&command=<cmd>  Admin pipe (upgrade to WS, bridges to node WS)
GET  /v1/admin/pipe?node=<CN>       Check if node WS is connected (REST)
```

## Advanced Pipeline

The ZFS send/recv pipe is fully configurable. Defaults use `zstd` compression with `-i` for single incremental sends.

**Pipe structure:**
```
Send: zfs send [opts] [buf_cmd |] [zip_cmd]       → chunk → blob
Recv: blob → chunk → [unzip_cmd |] [buf_cmd |] zfs recv [opts]
```

**Common configurations:**

```sh
# Raw encrypted send with no local compression (fast LAN)
zep-air config set send_options "-w"
zep-air config set pipe_zip_cmd ""

# All properties, all intermediate snapshots
zep-air config set send_options "-p"
zep-air config set send_all_snap 1

# mbuffer for rate-limited WAN links
zep-air config set pipe_send_buf_cmd "mbuffer -q -s 128k -m 512M"
zep-air config set pipe_recv_buf_cmd "mbuffer -q -s 128k -m 512M"

# lz4 instead of zstd
zep-air config set pipe_zip_cmd "lz4 -c"
zep-air config set pipe_unzip_cmd "lz4 -d"

# No compression (raw stream, fast CPU)
zep-air config set pipe_zip_cmd ""
zep-air config set pipe_unzip_cmd ""
```

## Architecture

```
zep-air-serve (single binary, single process)
├── MHD HTTPS server (GnuTLS)
├── SQLite DB (WAL mode)
│   ├── config        key-value store
│   ├── auth           certs + roles + cluster membership
│   ├── pushed         local push journal (per node)
│   ├── pulled         local pull journal (per node)
│   └── cluster_chain  authoritative GUID chain
├── blob storage       filesystem tree
│   └── <root>/<node>/<inverted_ts>-<guid>/meta.json + 0000..NNNN
├── zstream verify     decompress + zstream dump -v → extract GUIDs
└── cron engine        label scheduler + common-ground protection

zep-air (per-node agent)
├── pipeline push      zfs send → zstd → chunk → SHA256 → HTTPS PUT
├── pipeline pull      HTTPS GET → verify → reassemble → zstd -d → zfs recv
├── snap               local zfs snapshot with cluster-aware naming
├── rotate             count per label, purge oldest, skip protected
└── cron daemon        GET /sync → execute tasks → ack → rotate → sleep

zep-air-admin (remote management)
├── cluster            CRUD cluster definitions
├── join               register nodes with role + mapping
└── list/remove        node management
```

## Testing

```sh
sudo test/cluster_smoke.sh
```

Creates 3 isolated users (`za-master`, `za-client-1`, `za-client-2`) each with their own loopback ZFS pool, full PKI, TLS server, and runs 12 tests: full/incremental push, pull, GUID consistency, replica chain, idempotent pull, admin auth rejection, and node cert push. All over HTTPS with mutual TLS.
