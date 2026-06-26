# clientless

A clientless Diablo II 1.14d Battle.net client, in Zig. It speaks the wire protocols
directly — BNCS, MCP (realm/character), BNFTP, and the D2GS game protocol — with no game
binary, no wine, and no graphics. Point it at your own realm server (realmd, pvpgn) to
test it, or at a real gateway to study the protocol.

What it does:

- Version check (CheckRevision) and CD-key auth (`SID_AUTH_CHECK`).
- Account login and creation over OLS (the broken-SHA-1 password hash).
- Realm list and realm logon, then the MCP flow: character list, create, logon, ladder.
- Chat: enter chat, join a channel, talk, `/kick`.
- Game entry: create/join a game and hand off to the GS (`GAMELOGON`/`JOINGAME`).
- BNFTP file discovery and download (the `bnftp` binary).

It handles both the modern base64 CheckRevision challenge (real Battle.net) and the
legacy `A=1 B=1 …` formula (realmd/pvpgn), and can run keyless against a permissive realm.

## Build

Requires Zig 0.16.

    zig build          # -> zig-out/bin/{clientless,bnftp}
    zig build test     # CheckRevision / CD-key / xSHA-1 vectors

## Run

    clientless <host> [product] [version] [options]

    clientless realm.example.com D2XP 1.14.3.71 --login acct:pass
    clientless realm.example.com D2XP 1.14.3.71 --create acct:pass --game MyGame
    bnftp --head realm.example.com D2XP CheckRevision.mpq

Options: `--port`, `--keys K1,K2`, `--login`/`--create acct:pass`, `--game <name>`
(`--gs-port`), `--channel/--say/--kick/--listen`, `--sig0`, `--verbose`.

## The three hashes

Easy to conflate; they are distinct:

1. CheckRevision — standard SHA-1.
2. CD-key block — standard SHA-1 over `clientToken ++ serverToken ++ product ++ public ++ value`.
3. Account password — Blizzard's *broken* SHA-1 (`src/xsha1.zig`): single-bit-rotate
   message schedule, little-endian I/O, zero padding. `OLS = xsha1(ct ++ st ++ xsha1(lower(pw)))`.

## CI

`zig build` + `zig build test` run on every push. The `e2e` job builds realmd from the
d2gs source and drives a full session against it (auth → create → login → MCP → char →
ladder → chat); see `ci/e2e.sh`. Game entry needs a real GS (the proprietary `Game.exe`
under wine), so `ci/e2e-game.sh` runs only on a self-hosted runner with the D2 files.

## Notes

- Talking to live Battle.net sends your CD-keys and account credentials; that's on you
  (rate limits, ToS). Against your own realm it's just a test client.
- No keys or credentials are committed — they're arguments; tests use synthetic vectors.
- Sockets go through libc (`std.net` was dropped in Zig 0.16); native host target.
