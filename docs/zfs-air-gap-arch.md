# ZFS Air-Gap Replication Architecture

## Overview

Instead of direct SSH between nodes in the chain, each node pushes snapshots to an
intermediary (S3, SFTP, or similar), and downstream nodes pull from it:

```
master ──push──▶ [S3 / SFTP] ──pull──▶ middle ──push──▶ [S3 / SFTP] ──pull──▶ sink
```

No node has direct network access to any other node. The intermediary is the sole
communication channel.

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Lateral SSH movement | No SSH between nodes exists |
| Compromised master pushes bad data | Split-brain on downstream detects divergence |
| Compromised middle/sink | Can't reach other nodes; isolation is complete |
| Ransomware encrypts master | Downstream retains clean snapshots; rollback recovers |
| Attacker deletes snapshots on intermediary | S3 Object Lock / versioning prevents deletion |
| Intermediary compromise | Encrypted streams (`zfs send -w` raw + LUKS or client-side GPG) |

Each node needs only:
- **Master**: write access to its intermediary prefix
- **Middle/Sink**: read access to upstream prefix, write access to its own prefix
- **Root cron (rotation)**: local `--rotate`, no remote access needed

## Data Flow

### Push side (upstream node)
1. Create snapshot locally (`zfs snapshot`)
2. Pipe through `zfs send | zstd | encrypt` into chunked blobs
3. Upload blobs + metadata (GUID, snapshot name, checksum) to intermediary

### Pull side (downstream node)
1. Poll intermediary for new snapshots (list metadata, compare GUIDs against local)
2. Download blobs for any unseen snapshot
3. Pipe through `decrypt | zstd -d | zfs recv`
4. Verify integrity (checksum match)
5. Repeat for next hop in chain

## Metadata Format (per snapshot)

Each snapshot uploads a small metadata file alongside the data blobs:

```json
{
  "snapshot": "tank/data@zep_min1-2026-04-28-0142",
  "guid": "18413739470207610017",
  "base_guid": "711560544780759377",
  "label": "min1",
  "created": "2026-04-28T01:42:00Z",
  "host": "node1",
  "blobs": [
    {"part": 0, "size": 10485760, "sha256": "abc123..."},
    {"part": 1, "size": 5242880,  "sha256": "def456..."}
  ]
}
```

## Donor Discovery Without SSH

When a downstream node is missing common snapshots, it can't SSH to arbitrary peers
to find a donor. Instead:

1. Query the intermediary for the chain's snapshot catalog (all GUIDs from all nodes)
2. Find the newest GUID that exists both locally and in the intermediary's catalog
3. Pull from the intermediary's blobs for that GUID (any upstream node that uploaded it)

## Chunking & Resume

Full ZFS send streams can be large. Chunking with checksums enables:
- **Resume**: re-download only failed chunks
- **Parallelism**: download multiple chunks concurrently
- **Incremental**: for incremental streams, only changed blocks are sent

Chunk size trade-off: smaller chunks = better resume granularity, more API calls.

## Immutability via S3 Object Lock

S3 Object Lock in compliance mode prevents deletion of uploaded snapshots for a
configurable retention period. This protects against:
- Compromised node deleting its own uploaded data
- Malicious actor with S3 credentials destroying the replication chain

Combined with client-side encryption, the intermediary becomes a write-only,
append-only log that even a fully compromised node cannot destroy.

## Configuration Properties

| Property | Description |
|----------|-------------|
| `zep:airgap:type` | `s3` or `sftp` |
| `zep:airgap:endpoint` | Intermediary URL/host |
| `zep:airgap:bucket` | S3 bucket or SFTP path |
| `zep:airgap:prefix` | Prefix for this node's data |
| `zep:airgap:encrypt` | Encryption key path or `none` |
| `zep:airgap:chunk_size` | Max blob size before splitting |

## Open Questions

- **Streaming vs chunking**: Stream directly to S3 multipart upload, or chunk locally first?
- **Metadata store**: Use S3 object listing as the catalog, or maintain a separate metadata store?
- **Lock duration**: How long should S3 Object Lock retain snapshots beyond the ZFS retention window?
- **SFTP semantics**: No native object lock — use write-once directory per snapshot, or rely on filesystem permissions?
