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

```sh
mkdir pki

# CA
openssl genrsa -out pki/ca.key 4096
openssl req -x509 -new -nodes -key pki/ca.key -sha256 -days 3650 \
  -out pki/ca.crt -subj "/C=IT/O=CompEd/CN=Zep-Air testing"

# Server cert
openssl genrsa -out pki/server.key 2048
openssl req -new -key pki/server.key -out pki/server.csr \
  -subj "/C=IT/O=CompEd/CN=master.zep.lan"
cat > pki/server.ext << 'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in pki/server.csr -CA pki/ca.crt -CAkey pki/ca.key \
  -CAcreateserial -out pki/server.crt -days 365 -sha256 -extfile pki/server.ext

# Admin cert
openssl genrsa -out pki/admin.key 2048
openssl req -new -key pki/admin.key -out pki/admin.csr \
  -subj "/C=IT/O=CompEd/CN=admin"
cat > pki/client.ext << 'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in pki/admin.csr -CA pki/ca.crt -CAkey pki/ca.key \
  -CAcreateserial -out pki/admin.crt -days 365 -sha256 -extfile pki/client.ext

# Node certs (one per node — repeat for each)
for node in za-master za-client-1 za-client-2; do
    openssl genrsa -out "pki/${node}.key" 2048
    openssl req -new -key "pki/${node}.key" -out "pki/${node}.csr" \
        -subj "/C=IT/O=CompEd/CN=${node}"
    openssl x509 -req -in "pki/${node}.csr" -CA pki/ca.crt -CAkey pki/ca.key \
        -CAcreateserial -out "pki/${node}.crt" -days 365 -sha256 -extfile pki/client.ext
done
```

### 3. Server setup and start

```sh
# One-time: register CA, server cert, and admin cert
zep-air-serve --setup \
  --cert pki/server.crt --key pki/server.key --ca pki/ca.crt \
  --admin-cert pki/admin.crt

# Start the server
zep-air-serve --port 8443 \
  --cert pki/server.crt --key pki/server.key --ca pki/ca.crt &
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
  --cert pki/admin.crt --key pki/admin.key --ca pki/ca.crt \
  cluster set --file cluster.json
```

### 5. Register nodes

```sh
# Master — maps cluster pool/fs to local pool/fs
zep-air-admin \
  --server https://master.zep.lan:8443 \
  --cert pki/admin.crt --key pki/admin.key --ca pki/ca.crt \
  join --role master --cluster prod --node za-master \
  --cert pki/za-master.crt \
  --map "tank-prod/data:rpool/master, tank-prod/home:rpool/master-home"

# Client — maps to its own local pool/fs, overrides retention
zep-air-admin \
  --server https://master.zep.lan:8443 \
  --cert pki/admin.crt --key pki/admin.key --ca pki/ca.crt \
  join --role client --cluster prod --node za-client-1 \
  --cert pki/za-client-1.crt \
  --map "tank-prod/data:vault/data(day:90,month:12), tank-prod/home:vault/home"
```

### 6. Configure nodes and run

**Master (`za-master`):**
```sh
zep-air config set node_name za-master
zep-air config set server_url https://master.zep.lan:8443
zep-air config set cert_path pki/za-master.crt
zep-air config set key_path  pki/za-master.key
zep-air config set ca_path   pki/ca.crt
zep-air config set cluster prod
zep-air config set mapping "tank-prod/data:rpool/master, tank-prod/home:rpool/master-home"

zep-air cron --daemon
```

**Client (`za-client-1`):**
```sh
zep-air config set node_name za-client-1
zep-air config set server_url https://master.zep.lan:8443
zep-air config set cert_path pki/za-client-1.crt
zep-air config set key_path  pki/za-client-1.key
zep-air config set ca_path   pki/ca.crt
zep-air config set cluster prod
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
| `cert_path` | Path to this node's TLS client cert |
| `key_path` | Path to this node's TLS private key |
| `ca_path` | Path to CA certificate |
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
  --cert, -c FILE       Server TLS certificate (PEM)
  --key, -k FILE        Server TLS private key (PEM)
  --ca, -a FILE         CA certificate for client auth (PEM)
  --admin-cert FILE     Admin client cert for --setup mode (PEM)
  --db, -D FILE         SQLite database path
  --verbose, -v         Verbose logging
```

### `zep-air-admin`

```
zep-air-admin [global options] <command> [args]

Global:
  --server, -s URL      Server URL
  --cert, -c FILE       Admin client certificate
  --key, -k FILE        Admin client key
  --ca, -C FILE         CA certificate

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
