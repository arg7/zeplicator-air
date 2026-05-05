# S3 Implementation Notes for ZFS Air-Gap Replication

## Key Design: Index-Free, Self-Describing Snapshots

No central metadata index. Each snapshot writes self-contained objects at deterministic
key paths. Downstream discovers new snapshots via S3 LIST.

## Object Layout

```
s3://zep-replication/
  node1/
    5845263190-18413739470207610017/        ← most recent (inverted timestamp + GUID)
      meta.json                             ← snapshot metadata
      0001                                  ← data blob
      0002                                  ← data blob
    5845263191-711560544780759377/           ← next recent
      meta.json
      0001
  node2/
    5845263190-9999999999/
      meta.json
      0001
```

## Inverted Timestamp for Reverse-Chronological LIST

S3 LIST returns keys in ascending lexicographic order. To get the most recent
snapshots first, prefix keys with an inverted Unix timestamp:

```
key_prefix = str(MAX_UINT32 - unix_timestamp)
```

`MAX_UINT32 = 9999999999` (10 digits) covers dates through year 2286.
Most recent snapshots have the smallest prefix value, appearing first in LIST results.

Single call: `LIST prefix=node1/ max-keys=20` returns the 20 newest snapshots.

## meta.json Schema

```json
{
  "snapshot": "tank/data@zep_min1-2026-04-28-0142",
  "guid": "18413739470207610017",
  "base_guid": "711560544780759377",
  "label": "min1",
  "created": "2026-04-28T01:42:00Z",
  "host": "node1",
  "stream_size": 15728640,
  "blob_count": 2,
  "blobs": [
    {"part": 0, "size": 10485760, "sha256": "abc123..."},
    {"part": 1, "size": 5242880,  "sha256": "def456..."}
  ]
}
```

## Discovery Flow

**Incremental poll (cron, frequent):**
```
LIST prefix=node1/ max-keys=5
→ returns 5 most recent snapshot prefixes
→ GET each meta.json, compare GUIDs against local zfs list
→ pull blobs for any unseen GUID
```

**Initial sync or chain repair (rare):**
```
LIST prefix=node1/
→ paginate through all prefixes
→ intersect GUIDs with local zfs list
→ find newest common GUID
→ pull all snapshots after that point
```

## Atomicity & Integrity

- **S3 PUT is atomic** — a partial upload never replaces an existing object
- **S3 checksums** — CRC32C by default, SHA256 with additional checksum
- **Versioning** — enable on the bucket. Every PUT creates a new version.
  Corrupt writes are recoverable by reverting to the previous version.
- **Object Lock** — compliance mode prevents deletion of recent snapshots.
  Lock duration should exceed the ZFS retention window by a safety margin
  (e.g., ZFS keeps 90 days, S3 locks 120 days).

## Lifecycle & Retention

S3 Lifecycle Policies handle cleanup automatically:

```json
{
  "Rules": [
    {
      "Id": "expire-old-snapshots",
      "Status": "Enabled",
      "Filter": { "Prefix": "" },
      "ExpirationInDays": 120
    },
    {
      "Id": "cleanup-old-versions",
      "Status": "Enabled",
      "Filter": { "Prefix": "" },
      "NoncurrentVersionExpiration": { "NoncurrentDays": 7 }
    }
  ]
}
```

- Snapshots older than 120 days deleted automatically
- Old object versions (from failed/corrupt writes) cleaned up after 7 days
- No cron job, no script, no maintenance

## Cost Considerations

| Operation | Cost per 1000 | Monthly (1000 snaps, 50GB/mo) |
|-----------|---------------|-------------------------------|
| PUT (upload) | $0.005 | $5 |
| GET (download) | $0.0004 | $0.40 |
| LIST | $0.005 | ~$0.005 (one call per poll) |
| Storage (GB/month) | $0.023 | Varies with retention window |
| Object Lock | Included | $0 |

Primary cost driver is storage, not API calls. The index-free design avoids
LIST pagination costs entirely for incremental sync.

## No Append Required

S3 has no append operation. This design avoids the problem entirely:
- Each snapshot is a new set of objects under a unique GUID-based prefix
- No object is ever modified after creation
- No central index to update atomically
- Discovery is pull-based: downstream reads, upstream only writes
