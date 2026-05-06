# Zeplicator Air

Air-gapped ZFS replication over HTTPS with mutual TLS. No SSH between nodes — the `zep-air-serve` TLS server is the sole communication channel. Pure C, ~3500 LOC.

## Synopsis

```
master ──push──▶ [zep-air-serve] ──pull──▶ middle ──push──▶ [zep-air-serve] ──pull──▶ sink
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
```

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
POST   /v1/admin/clusters           Create cluster definition
GET    /v1/admin/clusters           List clusters
GET    /v1/admin/clusters/<name>    Get cluster
DELETE /v1/admin/clusters/<name>    Remove cluster
POST   /v1/admin/nodes              Register master/client
GET    /v1/admin/nodes              List nodes
DELETE /v1/admin/nodes/<cn>         Remove node
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
