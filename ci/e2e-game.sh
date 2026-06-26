#!/usr/bin/env bash
# ci/e2e-game.sh — clientless game-entry E2E: create + join a game and prove the GS
# admits the character. Unlike ci/e2e.sh (which stops at chat/ladder), this needs a real
# GS — the proprietary Game.exe under wine + data MPQs — so it can't run on public CI;
# use it locally or on a self-hosted runner.
#
# Two modes:
#   STACK_HOST set  -> target an already-running stack (realmd + embedded game edge + GS).
#                      Vars: STACK_HOST, STACK_PORT (BNCS), STACK_GSPORT (game edge).
#   otherwise       -> bring up realmd (fs, embedded edge) + a GS, then tear down.
#                      Vars: D2_DIR (d2gs checkout), D2GS_GAME_SRC (D2 install with MPQs),
#                            WINE (default: wine).
set -euo pipefail

CLIENT="${CLIENT:-./zig-out/bin/clientless}"
GAME="e2egame$$"
[ -x "$CLIENT" ] || { echo "no clientless binary at $CLIENT"; exit 2; }

assert_entry() {
  local out="$1"
  local fail=0
  chk() { echo "$out" | grep -qE "$1" && echo "  ok: $2" || { echo "  FAIL: $2"; fail=1; }; }
  chk 'MCP_CREATEGAME\].*=> created'           "game created on the GS"
  chk 'MCP_JOINGAME\] token=0x[0-9a-f]+ gs='   "join routed to the GS"
  chk '\[GS\] <- [0-9]+ bytes after GAMELOGON' "GS accepted GAMELOGON (char admitted)"
  chk '=> IN GAME'                             "entered the game (world stream)"
  [ "$fail" = 0 ] || { echo "GAME E2E FAILED"; exit 1; }
  echo "GAME E2E PASSED"
}

if [ -n "${STACK_HOST:-}" ]; then
  PORT="${STACK_PORT:-6112}"; GSPORT="${STACK_GSPORT:-4000}"
  echo "targeting running stack ${STACK_HOST}:${PORT} (game edge :${GSPORT})"
  OUT="$(timeout 60 "$CLIENT" "$STACK_HOST" D2XP 1.14.3.71 --port "$PORT" --gs-port "$GSPORT" \
        ${KEYS:+--keys "$KEYS"} ${VERBOSE:+--verbose} --create e2e:pw --game "$GAME" 2>&1 || true)"
  echo "$OUT" | grep -vE '^\s+[0-9a-f]{2} '
  [ -n "${LOGDIR:-}" ] && { mkdir -p "$LOGDIR"; printf '%s\n' "$OUT" > "$LOGDIR/client.log"; echo "client log -> $LOGDIR/client.log"; }
  assert_entry "$OUT"
  exit 0
fi

# ── bring up our own realmd + GS ──
: "${D2_DIR:?set D2_DIR to a d2gs checkout (realmd + d2gs.dll source)}"
: "${D2GS_GAME_SRC:?set D2GS_GAME_SRC to a D2 install dir (d2data.mpq etc.)}"
WINE="${WINE:-wine}"
P="${E2E_PORT:-6322}"; EDGE="${E2E_EDGE:-4122}"; GSADDR="127.0.0.1:14122"
DATA="$(mktemp -d)"; GDIR="$(mktemp -d)"; RLOG="$(mktemp)"; GLOG="$(mktemp)"
cleanup() { kill "${RPID:-0}" 2>/dev/null||true; pkill -f "$GDIR" 2>/dev/null||true; rm -rf "$DATA" "$GDIR"; }
trap cleanup EXIT

( cd "$D2_DIR" && zig build realmd-bin >/dev/null && zig build >/dev/null )  # realmd + d2gs.dll
REALMD_DATA_DIR="$DATA" REALMD_DURABLE_STORE=fs REALMD_EPHEMERAL_STORE=fs \
REALMD_BNET_PORT="$P" REALMD_D2CS_PORT="$((P+1))" REALMD_D2DBS_PORT="$((P+2))" \
REALMD_GS_PORT="$((P+3))" REALMD_HEALTH_PORT="$((P+4))" \
REALMD_GAME_PORT="$EDGE" REALMD_QQ_PORT="$EDGE" \
REALMD_REALM_ADDR=127.0.0.1 REALMD_GAME_ADDR=127.0.0.1 \
REALMD_MODERN_CHALLENGE=1 REALMD_PERMISSIVE_AUTH=1 REALMD_SEED_ACCOUNTS='e2e:pw' \
REALMD_TRACE="${VERBOSE:+1}" \
  "$D2_DIR/zig-out/bin/realmd" > "$RLOG" 2>&1 &
RPID=$!
for _ in $(seq 1 60); do grep -q listening "$RLOG" && break; sleep 0.5; done

# assemble + launch the GS (hardlink the D2 install, drop our DLLs), point it at our realmd
for f in "$D2GS_GAME_SRC"/*; do [ -f "$f" ] && ln -f "$f" "$GDIR/$(basename "$f")" 2>/dev/null || true; done
cp "$D2_DIR/zig-out/bin/dbghelp.dll" "$D2_DIR/zig-out/bin/d2gs.dll" "$GDIR/"
DLL="Z:$(echo "$GDIR/d2gs.dll" | tr '/' '\\')"
( cd "$GDIR" && WINEDEBUG=-all WINEDLLOVERRIDES="dbghelp=n" "$WINE" Game.exe -w -nosound --headless \
    --loaddll "$DLL" --d2gs --d2gs-boot --create-games \
    --d2cs "127.0.0.1:$((P+3))" --d2dbs "127.0.0.1:$((P+2))" --gs-addr "$GSADDR" > "$GLOG" 2>&1 ) &
for _ in $(seq 1 60); do grep -qi 'registered' "$RLOG" && break; sleep 1; done
grep -qi 'registered' "$RLOG" || { echo "GS did not register"; tail -20 "$GLOG"; exit 1; }
echo "realmd + GS up"

OUT="$(timeout 60 "$CLIENT" 127.0.0.1 D2XP 1.14.3.71 --port "$P" --gs-port "$EDGE" ${VERBOSE:+--verbose} --create e2e:pw --game "$GAME" 2>&1 || true)"
echo "$OUT" | grep -vE '^\s+[0-9a-f]{2} '
if [ -n "${LOGDIR:-}" ]; then
  mkdir -p "$LOGDIR"
  printf '%s\n' "$OUT" > "$LOGDIR/client.log"
  cp "$RLOG" "$LOGDIR/realmd.log"; cp "$GLOG" "$LOGDIR/gs.log"
  echo "logs -> $LOGDIR (client.log, realmd.log, gs.log)"
fi
assert_entry "$OUT"
