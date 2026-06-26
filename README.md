# clientless

A clientless Diablo II **1.14d** Battle.net client, written in Zig. It speaks the wire
protocols directly — **BNCS** (login), **MCP** (realm/characters), **BNFTP** (file transfer),
and the **D2GS** game protocol — with **no game binary, no wine, and no graphics**. One small
static binary connects, authenticates, picks a realm, creates/selects a character, joins a
game, and receives the live in-game packet stream.

## Why this exists

This is the **test client for [jaenster/d2-dedicated-server](https://github.com/jaenster/d2-dedicated-server)**
— a clean-room Zig reimplementation of the Diablo II closed-realm servers (the `realmd` triplet:
bnetd + d2cs + d2dbs, plus a headless game server).

To know that server actually works, you need something that talks the *client* side of the
protocol. The real game client is a closed-source Windows binary that needs graphics, wine, and
the proprietary data files — useless for automated testing. `clientless` is the answer: it drives
the **entire** client→server handshake from a script, so the server's auth, realm, character, and
game-join paths can be exercised **in CI and by hand**, on every commit, with no game install.

It's also a faithful, readable reference for how the 1.14d closed-Battle.net protocol works, and
it runs against real Battle.net too (it was validated end-to-end against a live gateway).

## What it can do

- **Version check** — computes the modern base64 CheckRevision response (`checkrev_core`,
  the 1.14d `CheckRevision.mpq` algorithm) and the CD-key auth blocks for `SID_AUTH_CHECK`.
- **Accounts** — log in to, or create, an account over OLS (Blizzard's broken-SHA-1 password hash).
- **Realm** — list realms and log on to one, then over **MCP**: list/create/select characters,
  read the ladder.
- **Chat** — enter chat, join a channel, send messages, `/kick`, and listen for events.
- **Game** — create or join a game and **enter it on the game server**: `GAMELOGON (0x68)` →
  wait for the GS `0x02` LoadSuccess → `JOINGAME (0x6b)`, then read the S→C game stream
  (opcode-framed; `0xAE` huffman blobs are decompressed) — character assignment, act load,
  unit spawns, stat updates, quests.
- **BNFTP** — discover and download server files (the `bnftp` subcommand).
- Works against **your own realm** (realmd/pvpgn) *and* **real Battle.net**; handles both the
  modern base64 challenge and the legacy `A=1 B=1 …` formula; runs **keyless** on a permissive realm.

## What it can't (and won't) do

- **It is not a bot.** It performs the join handshake, parses the incoming packet stream, and
  prints what it sees — but it does **not** model game state (no player/unit/position tracking)
  and does **not** act in the world (no movement, no skills, no item pickup). It's a protocol
  harness, not an automation framework.
- **It doesn't stay in-game.** After joining it reads the stream for a short window and exits;
  there's no long-lived session / keep-alive loop.
- **No native Windows binary.** The socket layer is POSIX; on Windows run it via the container
  (Docker Desktop / WSL2). A Winsock port is possible but not done.
- **Classic challenge is a placeholder.** Against the legacy `A=1 B=1 …` formula it sends a
  placeholder hash, which only a permissive realm accepts — it does not compute a real classic
  CheckRevision (that needs the game files).
- **No anti-cheat work.** It does not run, forge, or bypass the lockdown / extra-work
  (Warden-style) modules. Game entry doesn't require them, so it simply doesn't engage them; it
  won't be extended to defeat them on a live service.
- **One session per run, single-threaded.** No connection pooling, no concurrency.

## Install

Prebuilt native binaries are on the [Releases](https://github.com/jaenster/d2-clientless/releases)
page for **Linux** (x86_64, aarch64, armv7, riscv64), **macOS** (x86_64, aarch64), and **FreeBSD**
(x86_64, aarch64). Linux builds are static musl (no dependencies). Or run the [container](#container).

## Build

Requires **Zig 0.16**. Produces a single binary:

    zig build          # -> zig-out/bin/clientless
    zig build test     # crypto unit tests (CheckRevision / CD-key / xSHA-1)

## Usage

    clientless <host> [product] [version] [options]      # BNCS / MCP / chat / game
    clientless bnftp [options] <host> [product] [file]   # BNFTP file client

Run `clientless` with no arguments for the full, sectioned help. Common flags:

| flag | meaning |
|-|-|
| `--keys K1[,K2]` | 26-char CD-key(s); omit on a permissive realm |
| `--login acct:pass` / `--create acct:pass` | log in / register then log in |
| `--game <name>` (`--gs-port <n>`) | create + join a game and enter it on the GS |
| `--channel/--say/--kick/--listen <sec>` | chat |
| `--verbyte <n>` | GAMELOGON version byte (default 14 = 1.14d) |
| `--force-checkrev` | answer even if the version-check MPQ isn't `CheckRevision.mpq` |
| `--sig0` / `--delay <ms>` / `--verbose` | sigOk=0 / pace each step / hexdump all traffic |

### Examples

    # version check only — no keys, no account
    clientless useast.battle.net

    # full session on your own realm: create a char, chat, read the ladder
    clientless realm.example.com D2XP 1.14.3.71 --login me:pw --listen 20

    # create the account, then create + enter a game
    clientless realm.example.com D2XP 1.14.3.71 --create me:pw --game MyGame

    # two clients chatting; the operator kicks the other
    clientless realm.example.com --login op:pw --channel ops --kick rude

    # live Battle.net with real CD-keys (your account, your responsibility)
    clientless useast.battle.net D2XP 1.14.3.71 --keys K1,K2 --login acct:pw --game MyGame

    # BNFTP: a file's size, then download it
    clientless bnftp --head useast.battle.net D2XP CheckRevision.mpq
    clientless bnftp --out-dir . useast.battle.net D2XP CheckRevision.mpq

## How the game join works

`GAMELOGON (0x68)` carries the JOINGAME token + game hash + character name (the exact
`D2GSPacketClt0x68` field layout). The client first **waits for the GS's `0xAF`** connection
packet (like the real client's connecting loop), then sends `0x68`, reads the S→C stream **framed
by opcode + the engine's size table** (not length-prefixed), and sends `JOINGAME (0x6b)` only in
response to the server's `0x02` LoadSuccess. Compressed `0xAE` blobs are huffman-decompressed
(`src/huffman.zig`) and their inner packets parsed.

## The three hashes

Easy to conflate; they are distinct:

1. **CheckRevision** — standard SHA-1. `checkrev_core` implements the 1.14d `CheckRevision.mpq`
   algorithm specifically; against any other version-check MPQ it refuses to answer (so it never
   sends a wrong response) unless `--force-checkrev`.
2. **CD-key block** — standard SHA-1 over `clientToken ++ serverToken ++ product ++ public ++ value`.
3. **Account password** — Blizzard's *broken* SHA-1 (`src/xsha1.zig`): single-bit-rotate message
   schedule, little-endian I/O, zero padding.

## Container

    docker run --rm ghcr.io/jaenster/d2-clientless <host> D2XP 1.14.3.71 --login acct:pass
    docker run --rm ghcr.io/jaenster/d2-clientless bnftp --head <host> D2XP CheckRevision.mpq

Multi-arch (linux/amd64 + arm64), static musl on `scratch`. This is also how to run it on Windows
or macOS (Docker Desktop / WSL2), since there's no native binary for those yet.

## CI

`zig build` + `zig build test` run on every push. The `e2e` job checks out
[d2-dedicated-server](https://github.com/jaenster/d2-dedicated-server), builds `realmd`, and drives
a full session against it (auth → create → login → MCP → char → ladder → chat) — see `ci/e2e.sh`.
Game entry needs a real game server (the proprietary `Game.exe` under wine), so `ci/e2e-game.sh`
runs only on a self-hosted runner with the D2 files.

## Notes & credits

- Talking to live Battle.net sends your CD-keys and credentials — rate limits and ToS are your
  responsibility. Against your own realm it's just a test client.
- No keys or credentials are committed; they are arguments. Unit tests use synthetic vectors.
- The D2GS huffman tables in `src/huffman.zig` are ported from
  [jaenster/D2PacketBased](https://github.com/jaenster/D2PacketBased).
- Sockets go through libc (`std.net` was dropped in Zig 0.16); native host target.
