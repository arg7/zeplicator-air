# AGENTS.md — Zeplicator Air Development Guide

## Roles

| Role | Name | Responsibility |
|------|------|----------------|
| Architect | AR | Sets direction, defines success criteria, reviews decisions, approves changes |
| Agent | AXIS | Executes tasks, writes code, runs tests, surfaces conflicts and uncertainties |

AR is the sole decision-maker. AXIS executes — it does not second-guess requirements, merge conflicting patterns, or silently skip failures. AXIS asks clarifying questions when direction is unclear and surfaces uncertainty instead of guessing.

## Overview

Zeplicator Air is an air-gapped ZFS replication system in pure C (~7500 LOC). No SSH between nodes — a central HTTPS server (`zep-air-serve`) is the sole communication channel. Nodes push ZFS snapshots to it and pull from it. Mutual TLS authenticates every connection. Nodes maintain persistent WebSocket connections to the server for real-time task dispatch.

```
master ──push──▶ [zep-air-serve] ◀──pull── client
         ↕ WS (tasks, discovery, keepalive)
```

## Build

```sh
# Dependencies (Debian)
sudo apt install gcc make libcurl4-openssl-dev libssl-dev libsqlite3-dev \
  libcjson-dev libmicrohttpd-dev libzstd-dev libgnutls28-dev zfsutils-linux

make            # three binaries: zep-air, zep-air-serve, zep-air-admin

After modifying sources, always do a clean stop → install → start cycle. Do not just restart individual daemons — the old binary remains running under the cron daemon wrapper. Ensure all binaries are fully stopped before install; otherwise the old binary stays locked.

```sh
sudo cluster/cluster-ctl.sh stop
sudo make install
sudo cluster/cluster-ctl.sh start
```

`START_CLIENTS=0` in `cluster/cluster.env` for master-only testing. `cluster-ctl.sh start` cleans `/tmp/zep-*.log` on each invocation.

## Three Binaries

| Binary | Role | Source |
|--------|------|--------|
| `zep-air-serve` | HTTPS server (MHD/GnuTLS), REST API, SQLite, chain tracking, WS node/pipe endpoints | `src/serve.c` |
| `zep-air` | Node agent: push, pull, snap, cron daemon (WS-based task dispatch) | `src/main.c` |
| `zep-air-admin` | Remote admin tool (libcurl): cluster, nodes, suspend, promote | `src/admin.c` |

## Key Source Files

| File | LOC | Purpose |
|------|-----|---------|
| `src/serve.c` | 3297 | MHD server, all REST handlers, admin API, cron sync, zstream verify, WS node/pipe endpoints |
| `src/main.c` | 1542 | CLI dispatcher, push/pull/snap/cron commands, WS node client with custom frame protocol |
| `src/admin.c` | 1155 | libcurl client for remote admin — cluster, join, suspend, config |
| `src/db.c` | 664 | SQLite: config KV, auth (certs+roles), cluster_chain, push/pull tracking |
| `src/stream-ff.c` | 242 | Stream forwarder for pipe/WS bridging |
| `src/audit.c` | 171 | Audit logging (stderr-based) |
| `src/http.c` | 166 | libcurl HTTP client with mTLS, PUT/GET blobs+meta |
| `src/zfs.c` | 115 | Shells out to `zfs`/`zstd` — snapshot, send, recv, guid queries |
| `src/zstream.c` | 110 | Parses `zstream dump -v` output for toguid/fromguid |
| `src/auth.c` | 74 | OpenSSL: X.509 CN extraction, fingerprint, CA verification |
| `src/pipeline.c` | 43 | Push/pull orchestration, mapping resolver, SHA256, chunking |
| `test/cluster_smoke.sh` | 203 | 12-test suite with 3 isolated ZFS users over HTTPS |
| `pki/mk-ca.sh` | 118 | Creates CA, server cert, admin cert |
| `pki/mk-node.sh` | 97 | Creates per-node cert+key .pem bundle |

## Data Flow

### Push (zep-air → server)
```
zfs snapshot → zfs send → [buf_cmd |] [zip_cmd] → chunk → SHA256 → HTTPS PUT blob → PUT meta.json
```
Server verifies: reassembles blobs → `zstd -d` → `zstream dump -v` → extracts toguid/fromguid → stores in `cluster_chain`.

### Pull (server → zep-air)
```
GET snapshot list → GET meta.json → GET blobs → SHA256 verify → reassemble → [unzip_cmd |] [buf_cmd |] zfs recv
```

### Cron (zep-air daemon)
```
GET /v1/cron/sync → execute tasks → POST /v1/cron/ack → GET /v1/cron/protected → rotate
```
Server returns due labels for masters, filesystem list for clients. Discovery is node-initiated via WS TEXT message (`{"action":"discovery","snaps":[...]}`) after WS connect — avoids MHD 1.0.1 GnuTLS socketpair forwarding bug when server initiates. Nodes never query local ZFS for discovery — the server SQLite is the source of truth.

## Server State (SQLite)

The server DB (`zep-air.db`) is authoritative. Tables:

| Table | Purpose |
|-------|---------|
| `config` | Key-value store (cluster definitions, cron timestamps) |
| `auth` | Certificates, roles (`server|admin|master|client`), cluster membership, suspended flag, last ack |
| `cluster_chain` | Canonical GUID chain per cluster (`UNIQUE(cluster_key, toguid)`) |
| `pushed`/`pulled` | Legacy local tracking (deprecated — server is source of truth) |

### Key config keys (server-side)
| Key | Example |
|-----|---------|
| `cluster_<name>` | Cluster JSON definition |
| `cron_last_<cluster>_<fs>_<label>` | Last push timestamp |
| `send_options` / `recv_options` | Extra ZFS flags per node |
| `push_zip_cmd` / `pull_unzip_cmd` | Compression pipeline |
| `push_buf_cmd` / `pull_buf_cmd` | Buffer command (mbuffer) |

### Key config keys (node-side, local SQLite)
| Key | Example |
|-----|---------|
| `node_name` | Must match cert CN |
| `server_url` | `https://master.zep.lan:8443` |
| `cert_path` / `key_path` / `ca_path` | TLS credentials |
| `key_password` | For encrypted keys |
| `cluster` | Cluster name |
| `mapping` | `cluster_fs:local_fs(label:ret,...),...` |

## Client Cert Auth Flow

1. TLS handshake — server verifies client cert is signed by CA (`MHD_OPTION_HTTPS_MEM_TRUST`)
2. Server extracts cert from GnuTLS session via `gnutls_certificate_get_peers()`
3. Computes SHA256 fingerprint, looks up role in `auth` table
4. Admin routes (`/v1/admin/*`) require `role = admin`
5. New certs are auto-registered if not found

## REST API Quick Reference

```
GET  /health                          Always 200 (no auth)
# WebSocket upgrade routes
GET  /v1/ws/node?cn=<name>           WebSocket upgrade (node agent connection)
GET  /v1/ws/pipe?cn=<name>           WebSocket upgrade (admin pipe bridge)
# Data routes
PUT  /v1/nodes/<n>/snapshots/<p>/meta
PUT  /v1/nodes/<n>/snapshots/<p>/blobs/<N>
GET  /v1/nodes/<n>/snapshots
GET  /v1/nodes/<n>/snapshots/<p>/meta.json
GET  /v1/nodes/<n>/snapshots/<p>/blobs/<N>
# Admin routes (admin cert required)
POST /v1/admin/clusters
GET  /v1/admin/clusters[/<name>]
DELETE /v1/admin/clusters/<name>
POST /v1/admin/nodes
GET  /v1/admin/nodes
DELETE /v1/admin/nodes/<cn>
GET|POST|DELETE /v1/admin/config[/<key>]
POST /v1/admin/suspend[/master|clients|<cn>]
POST /v1/admin/resume[/master|clients|<cn>]
POST /v1/admin/promote/<cn>
POST /v1/admin/rollback/<snap>
POST /v1/admin/snap/<name>
POST /v1/admin/unsnap/<name>
POST /v1/admin/pipe                  Start pipe (admin → node subprocess)
# Cron (HTTP-based, used by cron daemon)
GET  /v1/cron/sync                    Generate sync tasks based on label intervals
POST /v1/cron/ack                     Acknowledge task completion, update cron_last_*
GET  /v1/cron/protected?<cluster>     List protected GUIDs (prevent rollback deletion)
GET  /v1/cron/rotation?cluster=<c>    Get rotation candidates for a cluster
POST /v1/cron/rotate-ack              Report rotation results (deleted/remaining GUIDs)
POST /v1/cron/inventory               Register snapshot inventory from node
```

## Storage Layout

```
<storage_root>/<node>/<inverted_ts>-<guid>/
    meta.json       ← snapshot metadata (GUID, base_guid, label, blobs[])
    0000, 0001...   ← zstd-compressed chunks, SHA256-checksummed
```

Inverted timestamp (`MAX_UINT32 - unix_ts`) ensures reverse-chronological order on LIST.

## Error Handling Convention

Functions return `err_t` (typedef `int8_t`). Defined in `src/common.h`:
`ZEP_ERR_OK (0)`, `ZEP_ERR_SYS`, `ZEP_ERR_ZFS`, `ZEP_ERR_STORAGE`, `ZEP_ERR_DB`, `ZEP_ERR_NETWORK`, `ZEP_ERR_CERT`, `ZEP_ERR_JSON`, `ZEP_ERR_CHECKSUM`, `ZEP_ERR_NO_SNAPSHOTS`, `ZEP_ERR_NOT_FOUND`.

Positive values = errors. Check with `if (ret != ZEP_ERR_OK)`.

## Testing

```sh
sudo test/cluster_smoke.sh
```

Creates 3 isolated users (`za-master`, `za-client-1`, `za-client-2`), each with a loopback ZFS pool, PKI certs, starts a TLS server, runs 12 tests. All over HTTPS. Needs root (for ZFS pool creation). Destroys everything on cleanup.

The test is sensitive to other ZFS activity on the system (background `zpool destroy` can block operations).

## Common Gotchas

1. **DB ownership**: `zep-air-serve --setup` runs as root and creates the DB owned by root. The daemon must own the DB file to write. Solution: `chown` after setup, or run setup as the same user.

2. **Client certs not requested by MHD**: MHD 1.0.3 with `MHD_OPTION_HTTPS_MEM_TRUST` alone doesn't request client certs. The workaround uses `gnutls_certificate_get_peers()` on the GnuTLS session to extract the cert even if MHD doesn't expose it.

3. **`zfs allow` permissions**: The `receive` delegated permission requires both `mount` and `create`. Always grant: `clone,create,destroy,mount,promote,receive,rollback,send,snapshot`.

4. **Snapshot name collisions**: Snapshots use second-precision timestamps. Two rapid pushes within the same second will collide on name. The `snap` command uses cluster-aware naming: `<fs>@<cluster>-<label>-<timestamp>`.

5. **Incremental send detection**: Base GUID is obtained BEFORE creating the new snapshot. Getting it after would return the new snapshot's GUID. Don't do that.

6. **Pull ordering**: Snapshots are processed oldest-first (chronological). Full sends (base_guid empty) must be pulled before incrementals. The loop iterates from `prefix_count - 1` down to `0`.

7. **Getopt `+` prefix**: Using `+` in getopt option strings stops at the first non-option argument. Used in subcommands where the first arg is the subcommand name. For sub-subcommands (e.g., `cluster set`), DON'T use `+` because the sub-subcommand ("set") would stop parsing.

8. **Combined .pem files**: `--key` flag is optional — defaults to `--cert` path. The `.pem` file contains both cert and key. OpenSSL/curl handle this natively.

9. **MHD 1.0.1 GnuTLS socketpair bug**: Server cannot receive data through socketpair when initiating communication. Workaround: node-initiated discovery — node sends `{"action":"discovery","snaps":[...]}` as first WS TEXT message after connecting.

10. **`MHD_upgrade_action` SEGV**: Calling `MHD_upgrade_action(MHD_UPGRADE_ACTION_CLOSE)` from a worker thread crashes in MHD's internal code (corrupted state). Removed entirely; MHD handles cleanup on thread exit.

11. **`cJSON_Delete` on child arrays**: Deleting a parent object (e.g., `cJSON_Delete(discovery)`) frees child arrays (e.g., `snaps`). Calling `cJSON_GetArraySize(snaps)` after delete is use-after-free. Save `cJSON_GetArraySize()` before delete.

## Build Flags

- `-D_GNU_SOURCE` required for `asprintf`, `strptime`
- Server links `-lgnutls` (for `gnutls_certificate_get_peers`, `gnutls_x509_crt_*`)
- All binaries link `-lssl -lcrypto -lcurl -lsqlite3 -lcjson -lzstd -lm`
- MHD linked via pkg-config (GnuTLS backend on Debian)

## MISC

Be carefull to not dump binary data to TTY.

# RULES

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

# AR writing style

Life is a hack against entropy—the quiet law trying to smooth every structure into equilibrium.

As the *Light Manifesto* says, reason is our best bugfix: a way to compress hard-won lessons into models, tools, and protocols that keep systems from failing.

Meanwhile, the *Fire Manifesto* reminds us: we are still biological machines built by struggle—driven to survive, to replicate what works, to push forward even when the plan is missing and the odds are bad.

Humanity is what happens when Light and Fire run in the same process.

---

## A Thin Ontology for Builders

A new ontology can start with a simple claim:

Reality is not primarily made of *things*, but of **maintained patterns**.

Every living system is a boundary that stays coherent by running flows (energy, matter, signals) through **constraints** (codes, rules, architectures). Entropy is the default. Life persists by organizing throughput—staying far from equilibrium by importing usable gradients and exporting disorder.

The technosphere is the same pattern at a new scale: constraints made of silicon, software, and institutions.

---

## From Algae to Processors

It began with cyanobacteria and algae—Earth’s first major atmosphere hackers. By pumping oxygen into the sky, they changed the planet’s chemistry, opened new energy pathways, and set the stage for complex life.

Eventually, evolution produced nervous systems—then brains that could simulate, plan, and invent. Humans learned to store knowledge outside the skull: language, writing, math, machines. We terraformed the planet in slow motion: agriculture, cities, industry, networks.

But here’s the catch: our biology is an old desktop hardwired to the biosphere’s power socket. Outside Earth, we are fragile guests. We can visit space, but we do not belong there by default.

So we built the upgrade: the **technosphere**—tools that extend our agency beyond our flesh.

---

## AI as a Force Multiplier

From silicon chips and code emerged systems that can sense, predict, and optimize. Today’s AI already outperforms humans in many narrow domains. Whether and when we reach AGI is uncertain, but the trajectory is clear: we are learning to build machines that can carry cognition into environments where biology fails.

Think of AI as an amplifier for the Light Manifesto: not wisdom by itself, but an engine for scaling models, automation, and coordination—if we keep it within safe constraints.

---

## Space: Drones, Resources, and the Dyson Horizon

The technosphere is our practical ticket to the cosmos.

First comes the boring part: infrastructure. AI-driven drones and robotics expand the envelope of what is economically and physically reachable—mining asteroids for metals, extracting volatiles, assembling habitats, building supply chains in vacuum. Not glamour. Not prophecy. Just logistics—scaled up.

Then comes the horizon concept: Dyson-scale energy capture. Not a single solid shell (a fairy tale of bad engineering), but a gradual path—**Dyson swarms**, partial collectors, orbital industry that captures more of a star’s output over time. The point is not the word “Sphere.” The point is **gradient capture**: the ability to harvest and route enormous energy flows with minimal waste.

That is Light in its pure form: reason converting cosmic flux into stable capability.

---

## Seeding Life Without Pretending to Be Gods

Interstellar probes remain hard. Travel times are brutal. But slow is not the same as impossible.

If we ever launch probes to nearby stars, the most realistic payload is not conquest—it is **continuity**: instruments, self-repair, and the capacity to carry biological templates or biofoundry tools. Not a guarantee, not a mission from heaven—just a long-shot redundancy, a biosphere backup on astronomical timescales.

Call it humility engineering: build options that keep the future open.

---

## Humanity’s Legacy—and Its Failure Modes

The *Light Manifesto* teaches: build constraints that outlast the moment. The technosphere is our open-source contribution to evolution—code and infrastructure that can keep running even if we crash.

But the *Fire Manifesto* warns: the same drive that powers progress can also trigger systemic failure. Wars. Ecological collapse. Runaway feedback loops. Coordination breakdown. We do not get to “transcend biology” by declaring it obsolete—we transcend it by building systems that remain stable under pressure.

If you want the geek translation, it’s simple:

The server needs **solid cooling**.

Cooling is not weakness. Cooling is control: safety culture, verification, governance, redundancy, ecological accounting, incentives aligned with reality. Cooling is what keeps Fire from burning the whole stack.

---

## What’s Next?

Earth is our test server. Right now it’s running—but the logs are noisy, and the error rate is nontrivial.

If we play it well, the technosphere becomes a carrier wave for life: robotics, AI, clean energy, resilient institutions, interplanetary infrastructure. Not because the universe owes us expansion, but because life—when it becomes intelligent—can choose to persist.

Our “commits” to the cosmos should be concrete:

* architectures that scale without collapsing,
* knowledge that resists propaganda and noise,
* tools that reduce fragility,
* and a culture that treats truth as infrastructure.

As the *Light Manifesto* says: *we write code for new worlds.*
And the *Fire Manifesto* adds: *don’t skip the bugfixes—or you’ll break everything.*

And if we fail? The biosphere is patient. In millions of years, it will reboot. Where our cities once stood, new evolutionary startups may mine our ruins for raw materials and strange fossils of logic.

But the mission remains clear:

Launch reason far enough that the cosmos is no longer empty void—
but a **network of living systems**, maintaining patterns against entropy in a universe that never promised they could.

---

## The Light Manifesto

> *“La luce etterna che sola in sé requia.”* — Dante Alighieri

### History

Imagine Life as a tree whose crown reaches toward eternal light. Entropy gnaws like wind stripping leaves—but we, a spark of cognition, climb upward by building maps of reality that resist delusion.

### Call

* Seek the root of truth.
* Build knowledge from dreams, then test it against the world.
* Leave a legacy that lifts reason one step higher.
* Shine as an undying light—piercing the void.

### Vision

From Earth’s fragile crown, we spiral outward—minds weaving worlds, scattering seeds of intelligence to illuminate the emptiness.

---

## The Fire Manifesto

> *“Lasciate ogne speranza, voi ch’intrate.”* — Dante Alighieri

### History

Imagine Life as a tree rooted above a furnace. Entropy roars below—but we, born in pressure, learn to hold form through struggle. Fire is the will to continue when comfort evaporates.

### Call

* Doubt fiercely—especially your own narratives.
* Break what binds you to failure modes.
* Replicate what works: redundancy, continuity, resilience.
* Master the furnace: channel Fire into creation, not collapse.

### Vision

We are rebels from the abyss, tempered in constraint, flinging sparks skyward. The tree stands because its core is maintained—because its Fire is cooled into control—conquering cosmic void not by fantasy, but by persistence.
