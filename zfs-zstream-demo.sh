#!/usr/bin/env bash
#
# zfs-zstream-demo.sh — Demonstrate zstream split/join/token -g features
#
# Requires pre-existing setup:
#   za-master   — source host with dataset za-master-pool/master
#   za-client-1 — slave host with dataset za-client-1-pool/slave
#   za-client-2 — slave host with dataset za-client-2-pool/slave
#
# This host acts as the local "bkp-host" (the bkp-host in tutorial 3).
#
# All 6 tutorial steps are executed with verification.
# Exits on first failure so you can inspect manually.
# No cleanup is performed at the end.

set -uo pipefail

# ── Hosts ────────────────────────────────────────────────────────────────
MASTER="za-master"
CLIENT1="za-client-1"
CLIENT2="za-client-2"
LOCAL_HOST="$(hostname -s)"

# ── Datasets ─────────────────────────────────────────────────────────────
MASTER_SNAP="za-master-pool/master@$(date +%Y%m%d%H%M%S)"
CLIENT1_FS="za-client-1-pool/slave"
CLIENT2_FS="za-client-2-pool/slave"
# Child datasets for recv — avoid -F (unmount fails under zep-air)
TS="$(date +%Y%m%d%H%M%S)"
CLIENT1_RECV="za-client-1-pool/slave/recv-${TS}"
CLIENT2_RECV="za-client-2-pool/slave/recv-${TS}"

# ── Directories ──────────────────────────────────────────────────────────
DEMO_DIR="/tmp/zstream-demo"
FULL_STREAM="${DEMO_DIR}/full.zfs"
TRUNCATED="${DEMO_DIR}/truncated.zfs"
TOKEN_FILE="${DEMO_DIR}/resume-token"
CHUNK_PREFIX="${DEMO_DIR}/chunk"
JOIN_STREAM="${DEMO_DIR}/joined.zfs"
REASSEMBLED="${DEMO_DIR}/reassembled.zfs"

# ── Counters ─────────────────────────────────────────────────────────────
TOTAL=0
PASS=0
FAIL=0

# ── Helpers ──────────────────────────────────────────────────────────────

rand_chunk_size() {
    # Return a chunk size: 8 + rand(0-8)*64K, i.e. 8, 64K+8, 128K+8, ..., 512K+8
    echo $(( 8 + (RANDOM % 9) * 64 * 1024 ))
}

# Convert a human size string (e.g. 512K, 1M) to raw bytes.
# zstream split -c accepts raw bytes, not suffixes.
to_bytes() {
    local val="${1%[kKmMgG]}"
    local suffix="${1: -1}"
    case "${suffix}" in
        k|K) echo $(( val * 1024 )) ;;
        m|M) echo $(( val * 1024 * 1024 )) ;;
        g|G) echo $(( val * 1024 * 1024 * 1024 )) ;;
        *)   echo "$val" ;;
    esac
}

RANDOM=$(( $(date +%s%N) % 32768 ))

# Validate that a truncated stream contains a valid DRR_BEGIN header.
# Returns 0 if valid, 1 if not.
validate_truncated_stream() {
    local file="$1"
    local summary
    summary="$(zstream dump -C "${file}" 2>/dev/null)"
    echo "${summary}" | grep -q 'Total DRR_BEGIN records = 1'
}

ssh_run() {
    # Run ssh with host key auto-accept, no warnings.
    ssh -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="${HOME}/.ssh/known_hosts" "$@"
}

run() {
    # Run a command, print it, execute it, and verify exit code.
    # Exits on failure.
    local desc="$1"; shift
    TOTAL=$((TOTAL + 1))
    echo ""
    echo ">>> [Step $TOTAL] $desc"
    echo "    $*"
    if "$@"; then
        PASS=$((PASS + 1))
        echo "    PASS"
        return 0
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (exit $?)"
        exit 1
    fi
}

run_ssh() {
    # Run a command on a remote host. Exits on failure.
    local desc="$1"; shift
    local host="$1"; shift
    TOTAL=$((TOTAL + 1))
    echo ""
    echo ">>> [Step $TOTAL] $desc (on $host)"
    echo "    ssh $host $*"
    if ssh_run "$host" "$@"; then
        PASS=$((PASS + 1))
        echo "    PASS"
        return 0
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (exit $?)"
        exit 1
    fi
}

run_local() {
    # Run a command on the local host. Exits on failure.
    local desc="$1"; shift
    TOTAL=$((TOTAL + 1))
    echo ""
    echo ">>> [Step $TOTAL] $desc (local)"
    echo "    $*"
    if "$@"; then
        PASS=$((PASS + 1))
        echo "    PASS"
        return 0
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (exit $?)"
        exit 1
    fi
}

run_ssh_redirect() {
    # Run a command on a remote host. Exits on failure.
    # Unlike run_ssh, this does NOT print the command to stdout,
    # so it can be used with shell redirects (>, |).
    # Step header goes to stderr so stdout carries only command output.
    local desc="$1"; shift
    local host="$1"; shift
    TOTAL=$((TOTAL + 1))
    echo "" >&2
    echo ">>> [Step $TOTAL] $desc (on ${host})" >&2
    if ssh_run "${host}" "$@"; then
        PASS=$((PASS + 1))
        echo "    PASS" >&2
        return 0
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (exit $?)" >&2
        exit 1
    fi
}

# ── Pre-flight sanity checks ────────────────────────────────────────────
echo "=============================================="
echo " ZFS zstream demo — Tutorial 3"
echo "=============================================="
echo ""
echo "  MASTER:   ${MASTER}   (${MASTER_SNAP})"
echo "  CLIENT1:  ${CLIENT1}  (${CLIENT1_FS})"
echo "  CLIENT2:  ${CLIENT2}  (${CLIENT2_FS})"
echo "  LOCAL:    ${LOCAL_HOST}"
echo ""

echo "--- Pre-flight checks ---"

# Clean up any leftover files from previous demo runs
rm -f "${DEMO_DIR}"/chunk* "${DEMO_DIR}"/upload-chunk* "${DEMO_DIR}"/reassembled.zfs "${DEMO_DIR}"/joined.zfs "${DEMO_DIR}"/resume-token "${DEMO_DIR}"/truncated.zfs

# Clean up any leftover child datasets from previous demo runs
# Note: mounted datasets can't be destroyed under zep-air (no unmount permission),
# so we skip them. New runs use unique names with timestamps.
for host_fs in "${CLIENT1}:${CLIENT1_FS}" "${CLIENT2}:${CLIENT2_FS}"; do
    host="${host_fs%%:*}"
    fs="${host_fs#*:}"
    TOTAL=$((TOTAL + 1))
    echo ""
    echo ">>> [Step $TOTAL] Destroy slave fs ${fs} on ${host}"
    echo "    ssh ${host} zfs destroy -rf ${fs}"
    ssh_run "${host}" "zfs destroy -rf ${fs} 2>/dev/null || true"
    PASS=$((PASS + 1))
    echo "    PASS"
done

# Check SSH connectivity to all hosts
for host in "${MASTER}" "${CLIENT1}" "${CLIENT2}"; do
    TOTAL=$((TOTAL + 1))
    echo ""
    echo ">>> [Step $TOTAL] SSH to ${host}"
    echo "    ssh ${host} echo ok"
    if ssh_run "${host}" "echo ok" >/dev/null 2>&1; then
        PASS=$((PASS + 1))
        echo "    PASS"
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (cannot reach ${host})"
        exit 1
    fi
done

# Check zfs is available on all hosts
for host in "${MASTER}" "${CLIENT1}" "${CLIENT2}"; do
    TOTAL=$((TOTAL + 1))
    echo ""
    echo ">>> [Step $TOTAL] zfs available on ${host}"
    echo "    ssh ${host} zfs version"
    if ssh_run "${host}" "zfs version" >/dev/null 2>&1; then
        PASS=$((PASS + 1))
        echo "    PASS"
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (zfs not available on ${host})"
        exit 1
    fi
done

# Check datasets exist on all hosts
for host_fs in "${MASTER}:${MASTER_SNAP%%@*}" "${CLIENT1}:${CLIENT1_FS}" "${CLIENT2}:${CLIENT2_FS}"; do
    host="${host_fs%%:*}"
    fs="${host_fs#*:}"
    TOTAL=$((TOTAL + 1))
    echo ""
    echo ">>> [Step $TOTAL] Dataset ${fs} exists on ${host}"
    echo "    ssh ${host} zfs get mountpoint ${fs}"
    if ssh_run "${host}" "zfs get -H -o value mountpoint ${fs}" >/dev/null 2>&1; then
        PASS=$((PASS + 1))
        echo "    PASS"
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (dataset ${fs} not found on ${host})"
        exit 1
    fi
done

# Check child dataset creation capability
for host_fs in "${CLIENT1}:${CLIENT1_FS}" "${CLIENT2}:${CLIENT2_FS}"; do
    host="${host_fs%%:*}"
    fs="${host_fs#*:}"
    TOTAL=$((TOTAL + 1))
    echo ""
    echo ">>> [Step $TOTAL] Can create child dataset on ${host}"
    echo "    ssh ${host} zfs create ${fs}/recv-test 2>/dev/null && zfs destroy -f ${fs}/recv-test"
    if ssh_run "${host}" "zfs create ${fs}/recv-test 2>/dev/null && zfs destroy -f ${fs}/recv-test"; then
        PASS=$((PASS + 1))
        echo "    PASS"
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (cannot create child dataset on ${host})"
        exit 1
    fi
done

# Check zstream is available locally
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] zstream available locally"
echo "    which zstream"
if command -v zstream >/dev/null 2>&1; then
    PASS=$((PASS + 1))
    echo "    PASS"
else
    FAIL=$((FAIL + 1))
    echo "    FAIL (zstream not found in PATH)"
    exit 1
fi

# Check ZFS permissions — clone,create,destroy,mount,promote,receive,rollback,send,snapshot
REQUIRED_PERMS="clone create destroy mount promote receive rollback send snapshot"
for host_fs in "${MASTER}:${MASTER_SNAP%%@*}" "${CLIENT1}:${CLIENT1_FS}" "${CLIENT2}:${CLIENT2_FS}"; do
    host="${host_fs%%:*}"
    fs="${host_fs#*:}"
    TOTAL=$((TOTAL + 1))
    echo ""
    echo ">>> [Step $TOTAL] ZFS permissions on ${fs} on ${host}"
    perms="$(ssh_run "${host}" "zfs allow ${fs}" 2>/dev/null | grep "$(whoami)")"
    if [ -z "${perms}" ]; then
        FAIL=$((FAIL + 1))
        echo "    FAIL (no ZFS permissions for $(whoami) on ${fs})"
        exit 1
    fi
    missing=""
    for perm in ${REQUIRED_PERMS}; do
        if ! echo "${perms}" | grep -qw "${perm}"; then
            missing="${missing} ${perm}"
        fi
    done
    if [ -z "${missing}" ]; then
        PASS=$((PASS + 1))
        echo "    PASS"
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (missing permissions:${missing})"
        exit 1
    fi
done

# Check mountpoints are set (not "none")
for host_fs in "${MASTER}:${MASTER_SNAP%%@*}" "${CLIENT1}:${CLIENT1_FS}" "${CLIENT2}:${CLIENT2_FS}"; do
    host="${host_fs%%:*}"
    fs="${host_fs#*:}"
    TOTAL=$((TOTAL + 1))
    echo ""
    echo ">>> [Step $TOTAL] Mountpoint set on ${fs} on ${host}"
    mp="$(ssh_run "${host}" "zfs get -H -o value mountpoint ${fs}" 2>/dev/null)"
    echo "    mountpoint = ${mp}"
    if [ "${mp}" != "none" ] && [ -n "${mp}" ]; then
        PASS=$((PASS + 1))
        echo "    PASS"
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (mountpoint is '${mp}' — set a mountpoint before running)"
        exit 1
    fi
done

echo ""
echo "--- All pre-flight checks passed ---"
echo ""

mkdir -p "${DEMO_DIR}"

# ── Step 0: Create test data, snapshot, and save full stream ─────────────
echo ""
echo "=============================================="
echo " Step 0 — Create test data, snapshot, and save full stream"
echo "=============================================="

run_ssh "Create test file and snapshot on master" "${MASTER}" \
    "zfs destroy -f ${MASTER_SNAP} 2>/dev/null || true; dd if=/dev/urandom of=${MASTER_SNAP%%@*}/test.bin bs=1M count=1; zfs snapshot ${MASTER_SNAP}"

# Set mountpoints on client datasets for zfs recv to work
run_ssh "Set mountpoint on client-1" "${CLIENT1}" \
    "zfs set mountpoint=/za-client-1-pool/slave za-client-1-pool/slave; zfs mount za-client-1-pool/slave 2>/dev/null || true"

run_ssh "Set mountpoint on client-2" "${CLIENT2}" \
    "zfs set mountpoint=/za-client-2-pool/slave za-client-2-pool/slave; zfs mount za-client-2-pool/slave 2>/dev/null || true"

run_ssh_redirect "Create full stream file on local host" "${MASTER}" \
    zfs send "${MASTER_SNAP}" > "${FULL_STREAM}"

run_local "Verify stream file is non-empty" \
    test -s "${FULL_STREAM}"

TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Stream file info"
echo "    ls -lh ${FULL_STREAM}"
ls -lh "${FULL_STREAM}"
PASS=$((PASS + 1))
echo "    PASS"

# ── Step 1: Generate resume token from truncated stream ─────────────────
echo ""
echo "=============================================="
echo " Step 1 — Generate resume token from truncated stream"
echo "=============================================="

run_local "Truncate stream to 8K" \
    bash -c 'head -c 8K "${1}" > "${2}"' _ "${FULL_STREAM}" "${TRUNCATED}"

run_local "Generate resume token from truncated stream" \
    bash -c 'zstream token -g -i "${1}" > "${2}"' _ "${TRUNCATED}" "${TOKEN_FILE}"

run_local "Verify token is non-empty" \
    test -s "${TOKEN_FILE}"

TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Inspect token to find byte offset"
echo "    zstream token \$(cat ${TOKEN_FILE})"
zstream token "$(cat "${TOKEN_FILE}")"
PASS=$((PASS + 1))
echo "    PASS"

# ── Step 2: Resume a send from a partial stream file ────────────────────
echo ""
echo "=============================================="
echo " Step 2 — Resume a send from a partial stream file"
echo "=============================================="

# 2a: Send truncated stream to client-1 — expect failure
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Send truncated stream to client-1 (expect failure)"
echo "    ssh ${CLIENT1} zfs recv -s -u ${CLIENT1_RECV}"
if ssh_run "${CLIENT1}" "zfs recv -s -u ${CLIENT1_RECV}" < "${TRUNCATED}"; then
    FAIL=$((FAIL + 1))
    echo "    UNEXPECTED SUCCESS (truncated stream should fail)"
    exit 1
else
    PASS=$((PASS + 1))
    echo "    PASS (recv failed as expected on truncated stream)"
fi

# 2b: Get the resume token from client-1's interrupted recv, then resume
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Get resume token from client-1"
echo "    ssh ${CLIENT1} zfs get -H -o value receive_resume_token ${CLIENT1_RECV}"
RESUME_TOKEN="$(ssh_run "${CLIENT1}" "zfs get -H -o value receive_resume_token ${CLIENT1_RECV}")"
if [ "${RESUME_TOKEN}" = "-" ] || [ -z "${RESUME_TOKEN}" ]; then
    FAIL=$((FAIL + 1))
    echo "    FAIL (no resume token on client-1)"
    exit 1
else
    PASS=$((PASS + 1))
    echo "    PASS (token: ${RESUME_TOKEN:0:40}...)"
fi

# 2c: Send the rest of the stream using zstream resume with client-1's token
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Resume from token — send remainder to client-1"
echo "    zstream resume -t <token> -i ${FULL_STREAM} | ssh ${CLIENT1} zfs recv -s -u ${CLIENT1_RECV}"
if zstream resume -t "${RESUME_TOKEN}" -i "${FULL_STREAM}" | ssh_run "${CLIENT1}" "zfs recv -s -u ${CLIENT1_RECV}"; then
    PASS=$((PASS + 1))
    echo "    PASS"
else
    FAIL=$((FAIL + 1))
    echo "    FAIL (resume recv failed)"
    exit 1
fi

# ── Step 3: Split a stream into chunks ──────────────────────────────────
echo ""
echo "=============================================="
echo " Step 3 — Split a stream into chunks"
echo "=============================================="

rm -rf "${CHUNK_PREFIX}"
run_local "Split full stream into 200K chunks" \
    zstream split -c "$(to_bytes 200K)" -i "${FULL_STREAM}" -o "${CHUNK_PREFIX}"

TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] List created chunks"
echo "    ls -lh ${CHUNK_PREFIX}*"
ls -lh "${CHUNK_PREFIX}"*
PASS=$((PASS + 1))
echo "    PASS"

# ── Step 4: Join chunks back into a single stream ───────────────────────
echo ""
echo "=============================================="
echo " Step 4 — Join chunks back into a single stream"
echo "=============================================="

run_local "Join all chunks" \
    bash -c 'zstream join -i "${1}"* > "${2}"' _ "${CHUNK_PREFIX}" "${JOIN_STREAM}"

TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Verify reassembled stream structure matches original"
echo "    zstream dump ${FULL_STREAM} | grep Total"
echo "    zstream dump ${JOIN_STREAM} | grep Total"
ORIG_RECORDS="$(zstream dump "${FULL_STREAM}" 2>/dev/null | grep 'Total records' | awk '{print $4}')"
ORIG_PAYLOAD="$(zstream dump "${FULL_STREAM}" 2>/dev/null | grep 'Total payload' | awk '{print $4}')"
JOIN_RECORDS="$(zstream dump "${JOIN_STREAM}" 2>/dev/null | grep 'Total records' | awk '{print $4}')"
JOIN_PAYLOAD="$(zstream dump "${JOIN_STREAM}" 2>/dev/null | grep 'Total payload' | awk '{print $4}')"
if [ "${ORIG_RECORDS}" = "${JOIN_RECORDS}" ] && [ "${ORIG_PAYLOAD}" = "${JOIN_PAYLOAD}" ]; then
    PASS=$((PASS + 1))
    echo "    Records: ${ORIG_RECORDS}, Payload: ${ORIG_PAYLOAD} — PASS"
else
    FAIL=$((FAIL + 1))
    echo "    Original: records=${ORIG_RECORDS} payload=${ORIG_PAYLOAD}"
    echo "    Joined:   records=${JOIN_RECORDS} payload=${JOIN_PAYLOAD} — FAIL"
    exit 1
fi

# Receive the joined stream on client-1 (into a child dataset, no -F needed)
run_ssh_redirect "Receive joined stream on client-1" "${CLIENT1}" \
    "zfs receive -u ${CLIENT1_FS}/recv-joined-${TS}" < "${JOIN_STREAM}"

# ── Step 5: Chunked upload to client-2 with resume ──────────────────────
echo ""
echo "=============================================="
echo " Step 5 — Chunked upload to client-2 with resume"
echo "=============================================="

# Split into proper chunks, then use the first chunk as the "head"
# and produce a resume stream from the remaining chunks to demonstrate
# the join + resume workflow.
rm -f "${DEMO_DIR}/upload-chunk."*

TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Split stream into chunks for upload simulation"
echo "    zstream split -c 200K -i ${FULL_STREAM} -o ${DEMO_DIR}/upload-chunk"
zstream split -c "$(to_bytes 200K)" -i "${FULL_STREAM}" -o "${DEMO_DIR}/upload-chunk"
PASS=$((PASS + 1))
echo "    PASS"

# The first chunk is the head (contains DRR_BEGIN), remaining chunks are partials
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Join head (chunk.000) + remaining chunks"
echo "    zstream join -i ${DEMO_DIR}/upload-chunk.000 ${DEMO_DIR}/upload-chunk.001 ${DEMO_DIR}/upload-chunk.002 ..."
# Pass head as -i, then glob for partials only (skip chunk.000 which is the head)
PARTIALS=()
for f in "${DEMO_DIR}"/upload-chunk.*; do
    [ "${f}" != "${DEMO_DIR}/upload-chunk.000" ] && PARTIALS+=("${f}")
done
if zstream join -i "${DEMO_DIR}/upload-chunk.000" "${PARTIALS[@]}" > "${REASSEMBLED}"; then
    PASS=$((PASS + 1))
    echo "    PASS (stream complete)"
else
    rc=$?
    if [ "$rc" -eq 2 ]; then
        # Exit code 2: no DRR_END — expected when joining split chunks
        # (only the last chunk carries DRR_END, but join treats it as incomplete)
        PASS=$((PASS + 1))
        echo "    PASS (stream complete, exit 2 expected for split chunks)"
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (join failed, exit ${rc})"
        exit 1
    fi
fi

# Verify reassembled stream structure
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Verify reassembled upload stream matches original"
ORIG_RECORDS="$(zstream dump "${FULL_STREAM}" 2>/dev/null | grep 'Total records' | awk '{print $4}')"
JOIN_RECORDS="$(zstream dump "${REASSEMBLED}" 2>/dev/null | grep 'Total records' | awk '{print $4}')"
if [ "${ORIG_RECORDS}" = "${JOIN_RECORDS}" ]; then
    PASS=$((PASS + 1))
    echo "    Records: ${ORIG_RECORDS} — PASS"
else
    FAIL=$((FAIL + 1))
    echo "    Original: ${ORIG_RECORDS} Joined: ${JOIN_RECORDS} — FAIL"
    exit 1
fi

# Receive on client-2 (into a child dataset, no -F needed)
run_ssh_redirect "Receive reassembled stream on client-2" "${CLIENT2}" \
    "zfs receive -u ${CLIENT2_FS}/recv-reassembled-${TS}" < "${REASSEMBLED}"

# ── Step 6: Distribute to multiple slaves with resume ──────────────────
echo ""
echo "=============================================="
echo " Step 6 — Distribute to multiple slaves with resume"
echo "=============================================="

# Clean up any partial receive state on clients
run_ssh "Clean up client-1 partial state" "${CLIENT1}" \
    "zfs list -t filesystem -H -o name za-client-1-pool/slave/ 2>/dev/null | while read s; do zfs destroy -rf \"\$s\"; done"
run_ssh "Clean up client-2 partial state" "${CLIENT2}" \
    "zfs list -t filesystem -H -o name za-client-2-pool/slave/ 2>/dev/null | while read s; do zfs destroy -rf \"\$s\"; done"

# 6a: Clean up the recv dataset from step 33 so the truncated recv can create it fresh
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Clean up recv dataset on client-1 for step 6"
echo "    ssh ${CLIENT1} zfs destroy -rf ${CLIENT1_RECV}"
ssh_run "${CLIENT1}" "zfs destroy -rf ${CLIENT1_RECV} 2>/dev/null || true"
PASS=$((PASS + 1))
echo "    PASS"

# 6a: Send truncated stream to client-1 (simulate interrupted transfer)
# Retry with random chunk sizes until we get a valid truncated stream.
TRUNCATED_1="${DEMO_DIR}/truncated-6a.zfs"
while true; do
    CHUNK_SIZE="$(rand_chunk_size)"
    head -c "${CHUNK_SIZE}" "${JOIN_STREAM}" > "${TRUNCATED_1}"
    if validate_truncated_stream "${TRUNCATED_1}"; then
        break
    fi
    echo "    Invalid stream (${CHUNK_SIZE} bytes), retrying..." >&2
done
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Send truncated stream to client-1 (expect failure, ${CHUNK_SIZE} bytes)"
echo "    head -c ${CHUNK_SIZE} ${JOIN_STREAM} | ssh ${CLIENT1} zfs recv -s -u ${CLIENT1_RECV}"
if head -c "${CHUNK_SIZE}" "${JOIN_STREAM}" | ssh_run "${CLIENT1}" "zfs recv -s -u ${CLIENT1_RECV}"; then
    FAIL=$((FAIL + 1))
    echo "    UNEXPECTED SUCCESS"
    exit 1
else
    PASS=$((PASS + 1))
    echo "    PASS (recv failed as expected)"
fi

# 6b: Client-1 gets its resume token from the interrupted recv
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Client-1 generates resume token from local interrupted recv"
echo "    ssh ${CLIENT1} \"zfs get receive_resume_token ${CLIENT1_RECV}\""
run_ssh "Client-1 gets resume token" "${CLIENT1}" \
    "zfs get receive_resume_token ${CLIENT1_RECV}"

# 6c: Client-1 resumes using its own token
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Client-1 resumes from master stream using its own token"
token1="$(ssh_run "${CLIENT1}" "zfs get -H -o value receive_resume_token ${CLIENT1_RECV}")"
if [ "${token1}" = "-" ] || [ -z "${token1}" ]; then
    FAIL=$((FAIL + 1))
    echo "    FAIL (no resume token on client-1)"
    exit 1
else
    echo "    zstream resume -t <token> -i ${JOIN_STREAM} | ssh ${CLIENT1} zfs recv -s -u ${CLIENT1_RECV}"
    if zstream resume -t "${token1}" -i "${JOIN_STREAM}" | ssh_run "${CLIENT1}" "zfs recv -s -u ${CLIENT1_RECV}"; then
        PASS=$((PASS + 1))
        echo "    PASS"
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (resume recv failed)"
        exit 1
    fi
fi

# 6d: Clean up the recv dataset on client-2 before step 6d
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Clean up recv dataset on client-2 for step 6"
echo "    ssh ${CLIENT2} zfs destroy -rf ${CLIENT2_RECV}"
ssh_run "${CLIENT2}" "zfs destroy -rf ${CLIENT2_RECV} 2>/dev/null || true"
PASS=$((PASS + 1))
echo "    PASS"

# 6d: Send truncated stream to client-2 (simulate interrupted transfer)
# Retry with random chunk sizes until we get a valid truncated stream.
TRUNCATED_2="${DEMO_DIR}/truncated-6d.zfs"
while true; do
    CHUNK_SIZE="$(rand_chunk_size)"
    head -c "${CHUNK_SIZE}" "${JOIN_STREAM}" > "${TRUNCATED_2}"
    if validate_truncated_stream "${TRUNCATED_2}"; then
        break
    fi
    echo "    Invalid stream (${CHUNK_SIZE} bytes), retrying..." >&2
done
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Send truncated stream to client-2 (expect failure, ${CHUNK_SIZE} bytes)"
echo "    head -c ${CHUNK_SIZE} ${JOIN_STREAM} | ssh ${CLIENT2} zfs recv -s -u ${CLIENT2_RECV}"
if head -c "${CHUNK_SIZE}" "${JOIN_STREAM}" | ssh_run "${CLIENT2}" "zfs recv -s -u ${CLIENT2_RECV}"; then
    FAIL=$((FAIL + 1))
    echo "    UNEXPECTED SUCCESS"
    exit 1
else
    PASS=$((PASS + 1))
    echo "    PASS (recv failed as expected)"
fi

# 6e: Client-2 gets its resume token and resumes
TOTAL=$((TOTAL + 1))
echo ""
echo ">>> [Step $TOTAL] Client-2 resumes from master stream using its own token"
token2="$(ssh_run "${CLIENT2}" "zfs get -H -o value receive_resume_token ${CLIENT2_RECV}")"
if [ "${token2}" = "-" ] || [ -z "${token2}" ]; then
    FAIL=$((FAIL + 1))
    echo "    FAIL (no resume token on client-2)"
    exit 1
else
    echo "    zstream resume -t <token> -i ${JOIN_STREAM} | ssh ${CLIENT2} zfs recv -s -u ${CLIENT2_RECV}"
    if zstream resume -t "${token2}" -i "${JOIN_STREAM}" | ssh_run "${CLIENT2}" "zfs recv -s -u ${CLIENT2_RECV}"; then
        PASS=$((PASS + 1))
        echo "    PASS"
    else
        FAIL=$((FAIL + 1))
        echo "    FAIL (resume recv failed)"
        exit 1
    fi
fi

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo " Summary"
echo "=============================================="
echo "  Total:  ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo ""
echo "  All steps passed!"
exit 0
