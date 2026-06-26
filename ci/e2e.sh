#!/usr/bin/env bash
# ci/e2e.sh — bring up realmd and drive the clientless client through a full session
# (auth -> account create -> login -> realm -> MCP -> char create/logon -> ladder).
# No redis, no CD-keys, no GS: realmd runs fs-only + permissive; the client is keyless
# and handles the classic CheckRevision challenge. Game entry (GAMELOGON) needs a real
# GS under wine and is out of scope for CI — that's exercised locally.
#
# Args: $1 = path to the realmd binary (default: d2gs/zig-out/bin/realmd)
#       $2 = path to the clientless binary (default: ./zig-out/bin/clientless)
set -euo pipefail

REALMD="${1:-d2gs/zig-out/bin/realmd}"
CLIENT="${2:-./zig-out/bin/clientless}"
[ -x "$REALMD" ] || { echo "no realmd binary at $REALMD"; exit 2; }
[ -x "$CLIENT" ] || { echo "no clientless binary at $CLIENT"; exit 2; }

DATA="$(mktemp -d)"
RLOG="$(mktemp)"
cleanup() { kill "${RPID:-0}" 2>/dev/null || true; rm -rf "$DATA"; }
trap cleanup EXIT

# Alt ports so CI/local never clash with anything on the default 6112/6113/6114.
PORT="${E2E_PORT:-6312}"

# realmd: fs store (no redis), permissive auth, modern challenge so the client exercises
# the real CheckRevision SHA-1; seed an account so --login is deterministic.
REALMD_DATA_DIR="$DATA" \
REALMD_DURABLE_STORE=fs REALMD_EPHEMERAL_STORE=fs \
REALMD_BNET_PORT="$PORT" REALMD_D2CS_PORT="$((PORT+1))" REALMD_D2DBS_PORT="$((PORT+2))" \
REALMD_GS_PORT="$((PORT+3))" REALMD_HEALTH_PORT="$((PORT+4))" \
REALMD_REALM_ADDR=127.0.0.1 REALMD_GAME_ADDR=127.0.0.1 \
REALMD_MODERN_CHALLENGE=1 REALMD_PERMISSIVE_AUTH=1 \
REALMD_SEED_ACCOUNTS='e2e:pw' \
  "$REALMD" > "$RLOG" 2>&1 &
RPID=$!

for _ in $(seq 1 60); do grep -q 'listening' "$RLOG" && break; sleep 0.5; done
grep -q 'listening' "$RLOG" || { echo "realmd did not come up"; cat "$RLOG"; exit 1; }
echo "realmd up:"; grep listening "$RLOG"

OUT="$(timeout 40 "$CLIENT" 127.0.0.1 D2XP 1.14.3.71 --port "$PORT" --create e2e:pw 2>&1 || true)"
echo "----- clientless output -----"; echo "$OUT"; echo "-----------------------------"

fail=0
check() { echo "$OUT" | grep -qE "$1" && echo "  ok: $2" || { echo "  FAIL: $2"; fail=1; }; }
check 'AUTH_CHECK\] result=0x0000'        "CheckRevision + AUTH_CHECK accepted"
check 'LOGONRESPONSE2.*result=0'           "OLS account login"
check 'MCP_STARTUP\] result=0x0'           "MCP realm session"
check 'MCP_CHARLOGON.*logged onto char'    "character logon"
check 'MCP_LADDERDATA'                      "ladder request"
check 'SID_ENTERCHAT\] unique name'        "entered chat"

[ "$fail" = 0 ] && echo "E2E PASSED" || { echo "E2E FAILED"; exit 1; }
