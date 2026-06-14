#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RSPAMD_IMAGE="${RSPAMD_IMAGE:-rspamd/rspamd:4.1.0}"
TMPDIR=$(mktemp -d)
CONTAINER=""
PORT=""

cleanup() {
    if [[ -n "$CONTAINER" ]]; then
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

start_rspamd() {
    local plugin=$1
    local config=$2
    local local_lua=${3:-}
    local args=(
        run -d --rm
        --name "rspamd-kam-runtime-$$-$RANDOM"
        -p 127.0.0.1::11333
        -v "$plugin:/etc/rspamd/plugins.d/kam.lua:ro"
        -v "$config:/etc/rspamd/rspamd.conf.local:ro"
    )

    if [[ -n "$CONTAINER" ]]; then
        docker rm -f "$CONTAINER" >/dev/null
    fi
    if [[ -n "$local_lua" ]]; then
        args+=(-v "$local_lua:/etc/rspamd/rspamd.local.lua:ro")
    fi
    args+=("$RSPAMD_IMAGE")
    CONTAINER=$(docker "${args[@]}")
    PORT=$(docker port "$CONTAINER" 11333/tcp | sed 's/.*://')

    for _ in $(seq 1 60); do
        if curl -fsS "http://127.0.0.1:$PORT/ping" >/dev/null 2>&1; then
            return
        fi
        sleep 0.25
    done
    docker logs "$CONTAINER"
    return 1
}

scan() {
    curl -fsS \
        -H "Content-Type: message/rfc822" \
        --data-binary "$1" \
        "http://127.0.0.1:$PORT/checkv2"
}

assert_symbol_score() {
    local symbol=$1
    local expected=$2
    python3 -c '
import json
import math
import sys

symbol, expected = sys.argv[1], float(sys.argv[2])
result = json.load(sys.stdin)
actual = result.get("symbols", {}).get(symbol)
if actual is None:
    raise SystemExit(f"{symbol} was not inserted: {result}")
if not math.isclose(float(actual["score"]), expected, rel_tol=0, abs_tol=1e-9):
    raise SystemExit(f"{symbol} score {actual['score']} != {expected}")
' "$symbol" "$expected"
}

assert_log() {
    local pattern=$1
    local logs
    logs=$(docker logs "$CONTAINER" 2>&1)
    if ! grep -Eq "$pattern" <<<"$logs"; then
        printf 'Container log did not match %s:\n%s\n' "$pattern" "$logs" >&2
        return 1
    fi
}

cd "$ROOT"
install -m 0644 dist/kam.lua "$TMPDIR/kam.lua"
install -m 0644 config/kam.conf "$TMPDIR/rspamd.conf.local"
start_rspamd "$TMPDIR/kam.lua" "$TMPDIR/rspamd.conf.local"

assert_log "loaded [0-9]+ generated KAM Lua rules"

scan $'From: a@example.com\nTo: b@example.com\nSubject: The TRUTH\n\nordinary text' |
    assert_symbol_score KAM_TRUTHINESS 1.5

scan $'From: a@example.com\nTo: b@example.com\nSubject: ordinary\n\nhttps://storage.googleapis.com/bucket-one/path/file.html https://storage.googleapis.com/bucket-two/path/file.html' |
    assert_symbol_score GB_STORAGE_GOOGLE_HTM 2.5

python3 - "$TMPDIR/dependency.lua" <<'PY'
import sys
from pathlib import Path

import kam_rspamd

source = (
    b"body LOCAL /dependency-trigger/\n"
    b"body BAD /(/\n"
    b"score BAD 1\n"
    b"meta DEP_META (LOCAL && AUDIT_EXTERNAL)\n"
    b"score DEP_META 2\n"
)
converted, _ = kam_rspamd.convert(
    source,
    "fixture://runtime",
    min_bytes=1,
    min_rules=1,
    external_symbols={"AUDIT_EXTERNAL"},
)
kam_rspamd.atomic_write(Path(sys.argv[1]), converted)
PY

cat > "$TMPDIR/rspamd.local.lua" <<'LUA'
rspamd_config:register_symbol({
  name = 'AUDIT_EXTERNAL',
  type = 'normal',
  priority = -10,
  score = 0.01,
  callback = function() return true end,
})
LUA
chmod 0644 "$TMPDIR/rspamd.local.lua"

start_rspamd \
    "$TMPDIR/dependency.lua" \
    "$TMPDIR/rspamd.conf.local" \
    "$TMPDIR/rspamd.local.lua"

scan $'From: a@example.com\nTo: b@example.com\nSubject: ordinary\n\ndependency-trigger' |
    assert_symbol_score DEP_META 2
assert_log "cannot compile KAM regexp BAD"

echo "Rspamd runtime tests passed"
