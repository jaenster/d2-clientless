# clientless

A clientless Diablo II 1.14d Battle.net client, in Zig. It speaks the wire protocols
directly — **BNCS** (login), **MCP** (realm/characters), **BNFTP** (file transfer), and the
**D2GS** game protocol — with no game binary, no wine, and no graphics. Point it at your own
realm (realmd, pvpgn) or a real gateway.

It goes the whole way: authenticate, pick a realm, create/select a character, create or join
a game, and **receive the live in-game packet stream** (character assignment, act load, units,
stats, quests) — all from a single ~2 MB binary.

## What it does

- **Version check** (CheckRevision) and **CD-key** auth (`SID_AUTH_CHECK`).
- **Account** login and creation over OLS (the Blizzard broken-SHA-1 password hash).
- **Realm** list + logon, then the **MCP** flow: character list / create / logon, ladder.
- **Chat**: enter chat, join a channel, talk, `/kick`.
- **Game entry**: create/join a game, hand off to the GS (`GAMELOGON` → `0x02` → `JOINGAME`),
  and parse the S→C game stream (opcode-framed, with `0xAE` huffman blobs decompressed).
- **BNFTP** file discovery + download (the `bnftp` subcommand).

It handles both the modern base64 CheckRevision challenge (real Battle.net) and the legacy
`A=1 B=1 …` formula (realmd/pvpgn), and can run keyless against a permissive realm.

## Build

Requires Zig 0.16. Produces one binary:

    zig build          # -> zig-out/bin/clientless
    zig build test     # crypto unit tests (CheckRevision / CD-key / xSHA-1)

## Usage

    clientless <host> [product] [version] [options]      # BNCS / MCP / chat / game
    clientless bnftp [options] <host> [product] [file]   # BNFTP file client

Run `clientless` with no arguments for the full option list. Highlights:

| flag |-|
|-|-|
| `--keys K1[,K2]` | 26-char CD-key(s); omit on a permissive realm |
| `--login acct:pass` / `--create acct:pass` | log in / register then log in |
| `--game <name>` (`--gs-port <n>`) | create + join a game and enter it on the GS |
| `--channel/--say/--kick/--listen <sec>` | chat |
| `--verbyte <n>` | GAMELOGON version byte (default 14 = 1.14d) |
| `--force-checkrev` | respond even if the version-check MPQ isn't `CheckRevision.mpq` |
| `--sig0` / `--delay <ms>` / `--verbose` | sigOk=0 / pace steps / hexdump all traffic |

### Examples

    # version check only (no keys/account)
    clientless useast.battle.net

    # full session on your own realm: create char, chat, read the ladder
    clientless realm.example.com D2XP 1.14.3.71 --login me:pw --listen 20

    # create the account, then create + enter a game
    clientless realm.example.com D2XP 1.14.3.71 --create me:pw --game MyGame

    # two clients chatting; the operator kicks the other
    clientless realm.example.com --login op:pw --channel ops --kick rude

    # live Battle.net with real CD-keys (your account, your risk)
    clientless useast.battle.net D2XP 1.14.3.71 --keys K1,K2 --login acct:pw --game MyGame

    # BNFTP: a file's size, then download it
    clientless bnftp --head useast.battle.net D2XP CheckRevision.mpq
    clientless bnftp --out-dir . useast.battle.net D2XP CheckRevision.mpq

## How the join works

`GAMELOGON (0x68)` carries the JOINGAME token + hash + char (the exact `D2GSPacketClt0x68`
struct layout). The client waits for the GS's `0xAF` connection packet before sending it, then
reads the S→C stream framed by opcode + the engine's size table — sending `JOINGAME (0x6b)` only
in response to the server's `0x02` LoadSuccess, exactly like the real client. Compressed `0xAE`
blobs are huffman-decompressed (`src/huffman.zig`) and their inner packets parsed.

## The three hashes

Easy to conflate; they are distinct:

1. **CheckRevision** — standard SHA-1. `checkrev_core` implements the 1.14d `CheckRevision.mpq`
   algorithm specifically; against a different version-check MPQ it refuses to answer (so it
   never sends a wrong response) unless `--force-checkrev`.
2. **CD-key block** — standard SHA-1 over `clientToken ++ serverToken ++ product ++ public ++ value`.
3. **Account password** — Blizzard's *broken* SHA-1 (`src/xsha1.zig`): single-bit-rotate
   message schedule, little-endian I/O, zero padding.

## Container

    docker run --rm ghcr.io/jaenster/d2-clientless <host> D2XP 1.14.3.71 --login acct:pass
    docker run --rm ghcr.io/jaenster/d2-clientless bnftp --head <host> D2XP CheckRevision.mpq

Multi-arch (linux/amd64 + arm64), static musl on `scratch`. No native Windows binary yet (the
socket layer is POSIX), but it runs under Docker Desktop / WSL2.

## CI

`zig build` + `zig build test` on every push. The `e2e` job builds realmd from the d2gs source
and drives a full session against it (auth → create → login → MCP → char → ladder → chat); see
`ci/e2e.sh`. Game entry needs a real GS (proprietary `Game.exe` under wine), so `ci/e2e-game.sh`
runs only on a self-hosted runner with the D2 files.

## Notes

- Talking to live Battle.net sends your CD-keys and credentials — rate limits and ToS are on
  you. Against your own realm it's just a test client.
- No keys or credentials are committed; they're arguments. The huffman tables in `src/huffman.zig`
  are ported from [jaenster/D2PacketBased](https://github.com/jaenster/D2PacketBased).
- Sockets go through libc (`std.net` was dropped in Zig 0.16); native host target.
