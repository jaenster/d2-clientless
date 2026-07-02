//! checkrev-probe — a clientless BNCS *version-check* client (protocol selector
//! 0x01), distinct from the BNFTP tool (selector 0x02). It points at a real
//! Battle.net server and exercises the version-check gauntlet end-to-end:
//!
//!   1. connect 0x01 → SID_AUTH_INFO (echoing the SID_PING cookie). The reply
//!      names the version-check MPQ + the base64 *challenge* (the "value string").
//!   2. compute the CheckRevision response with our portable core
//!      (`checkrev_core`, the same code the DLL and realmd use):
//!         response = base64( SHA1( first4(b64decode(challenge)) + ":"+ver+":" + sigOk ) )
//!   3. send SID_AUTH_CHECK carrying that response in the modern layout
//!      (dialog-result → EXE Version, first 4 base64 bytes → EXE Hash, rest →
//!      EXE Info) and print the server's result code.
//!
//! A version-error result (0x101/0x102) means our hash is wrong; a CD-key error
//! (0x2xx) means the *version check passed* (we send no real key). CD-key-free —
//! no account, no SRP, no login. Usage:
//!   zig build checkrev-probe -- <host> [product] [gameVersion] [--sig0]
const std = @import("std");
const core = @import("checkrev_core");
const cdkey = @import("cdkey");
const xsha1 = @import("xsha1");
const huffman = @import("huffman.zig");
const bnftp = @import("bnftp");
const packets = @import("game/packets.zig");
const world_mod = @import("game/world.zig");

// ── libc sockets (native host target; std.net/std.posix wrappers are gone in 0.16) ──
const Socket = c_int;
extern "c" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) c_int;
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: c_uint) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int; // variadic: mode only used with O_CREAT
extern "c" fn getentropy(buf: *anyopaque, n: usize) c_int; // CSPRNG seed (<=256B; macOS+glibc+musl)
extern "c" fn setsockopt(fd: c_int, level: c_int, optname: c_int, optval: *const anyopaque, optlen: c_uint) c_int;
const SOCK_STREAM: c_int = 1;

fn setRecvTimeout(fd: Socket, ms: u32) void {
    const tv = std.posix.timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    _ = setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, &tv, @sizeOf(std.posix.timeval));
}
extern "c" fn gettimeofday(tv: *std.posix.timeval, tz: ?*anyopaque) c_int;
fn nowMs() i64 {
    var tv: std.posix.timeval = undefined;
    _ = gettimeofday(&tv, null);
    return @as(i64, @intCast(tv.sec)) * 1000 + @divTrunc(@as(i64, @intCast(tv.usec)), 1000);
}

// --delay: pause before each protocol step. Real clients don't fire packets back-to-back;
// pacing avoids tripping server-side rate limits and gives the GS time to set up the game.
var step_delay_ms: u64 = 0;
const c_timespec = extern struct { tv_sec: c_long, tv_nsec: c_long };
extern "c" fn nanosleep(req: *const c_timespec, rem: ?*c_timespec) c_int;
fn pace() void {
    if (step_delay_ms == 0) return;
    const ts = c_timespec{ .tv_sec = @intCast(step_delay_ms / 1000), .tv_nsec = @intCast((step_delay_ms % 1000) * 1_000_000) };
    _ = nanosleep(&ts, null);
}

fn writeAll(fd: Socket, buf: []const u8) !void {
    var sent: usize = 0;
    while (sent < buf.len) {
        const n = write(fd, buf.ptr + sent, buf.len - sent);
        if (n <= 0) return error.WriteFailed;
        sent += @intCast(n);
    }
}

// Blizzard's live game farm (e.g. 158.115.201.x) also listens on :443, speaking the
// SAME D2GS protocol wrapped in TLS — the server greets unprompted (inside TLS) with
// 0xAF00 (NEGOTIATE_COMPRESSION). That 443 listener is NOT behind the per-IP firewall
// the d2cs JOINGAME whitelists for :4000, so it's an alternate game-entry transport.
// GsConn abstracts the GS leg so the join loop is identical over plaintext or TLS.
// The farm's cert is a real DigiCert wildcard *.diablo2.blizzard.com (O=Blizzard). A wildcard
// matches exactly ONE label, so the SNI must be e.g. <region>.diablo2.blizzard.com (the bare
// apex fails hostname matching). The subdomain very likely selects the region/backend.
const GsSni = "asia.diablo2.blizzard.com";
const GsConn = struct {
    fd: Socket,
    tls: ?*std.crypto.tls.Client = null,

    // Read available bytes (decrypted, for TLS). Returns >0 = bytes, 0 = EOF, <0 = idle/timeout.
    fn rd(self: *GsConn, buf: []u8) isize {
        if (self.tls) |c| {
            if (c.reader.buffered().len == 0) {
                c.reader.fillMore() catch |e| return if (e == error.EndOfStream) 0 else -1;
            }
            const avail = c.reader.buffered();
            if (avail.len == 0) return -1; // fill made no progress (timeout tick) — not EOF
            const m = @min(buf.len, avail.len);
            @memcpy(buf[0..m], avail[0..m]);
            c.reader.toss(m);
            return @intCast(m);
        }
        return read(self.fd, buf.ptr, buf.len);
    }

    fn wr(self: *GsConn, bytes: []const u8) !void {
        if (self.tls) |c| {
            try c.writer.writeAll(bytes);
            try c.writer.flush();
            return;
        }
        try writeAll(self.fd, bytes);
    }
};
fn connectResolved(gpa: std.mem.Allocator, host: []const u8, port: u16) !Socket {
    const chost = try gpa.dupeZ(u8, host);
    var pbuf: [8]u8 = undefined;
    const cserv = std.fmt.bufPrintZ(&pbuf, "{d}", .{port}) catch unreachable;
    var hints = std.mem.zeroes(std.c.addrinfo);
    hints.family = 0; // AF_UNSPEC
    hints.socktype = SOCK_STREAM;
    var res: ?*std.c.addrinfo = null;
    if (@intFromEnum(std.c.getaddrinfo(chost.ptr, cserv.ptr, &hints, &res)) != 0) return error.ResolveFailed;
    defer if (res) |r| std.c.freeaddrinfo(r);
    var ai = res;
    while (ai) |a| : (ai = a.next) {
        const sa = a.addr orelse continue;
        const fd = socket(a.family, SOCK_STREAM, 0);
        if (fd < 0) continue;
        if (connect(fd, sa, a.addrlen) == 0) {
            setRecvTimeout(fd, 20000);
            return fd;
        }
        _ = close(fd);
    }
    return error.ConnectFailed;
}

// Self-contained D2GS GAMELOGON probe against one (TLS) endpoint. Used by --gs-brute to fire a
// game's token/hash at MANY :443 gateways and see if any actually streams the game back. Returns
// what came back AFTER GAMELOGON so the caller can tell "routed our game" from "silently ignored".
const ProbeResult = struct {
    connected: bool = false,
    handshook: bool = false, // TLS ok (if tls) — got past the handshake
    af_greeted: bool = false, // saw the 0xAF D2GS greeting
    post_logon_bytes: usize = 0, // bytes received after we sent GAMELOGON
    saw_gameflags: bool = false, // 0x01
    saw_loadsuccess: bool = false, // 0x02
};
fn probeGateway(
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    use_tls: bool,
    sni: []const u8,
    ghash: u32,
    gtoken: u16,
    char_class: u8,
    ver_byte: u32,
    charname: []const u8,
    read_ms: i64,
) ProbeResult {
    var r: ProbeResult = .{};
    const fd = connectResolved(gpa, host, port) catch return r;
    defer _ = close(fd);
    r.connected = true;
    setRecvTimeout(fd, 4000);

    var threaded: std.Io.Threaded = undefined;
    var trbuf: [20480]u8 = undefined;
    var twbuf: [20480]u8 = undefined;
    var tcr: [20480]u8 = undefined;
    var tcw: [20480]u8 = undefined;
    var freader: std.Io.File.Reader = undefined;
    var fwriter: std.Io.File.Writer = undefined;
    var client: std.crypto.tls.Client = undefined;
    var conn: GsConn = .{ .fd = fd };
    if (use_tls) {
        threaded = std.Io.Threaded.init(gpa, .{});
        const tio = threaded.io();
        const f = std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } };
        freader = f.readerStreaming(tio, &trbuf);
        fwriter = f.writerStreaming(tio, &twbuf);
        var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
        if (getentropy(&entropy, entropy.len) != 0) return r;
        client = std.crypto.tls.Client.init(&freader.interface, &fwriter.interface, .{
            .host = .{ .explicit = sni },
            .ca = .no_verification,
            .read_buffer = &tcr,
            .write_buffer = &tcw,
            .entropy = &entropy,
            .realtime_now = .{ .nanoseconds = @as(i96, nowMs()) * 1_000_000 },
        }) catch return r;
        conn.tls = &client;
    }
    defer if (use_tls) threaded.deinit();
    r.handshook = true;

    var sbuf: [16384]u8 = undefined;
    var slen: usize = 0;

    // wait for the 0xAF greeting (up to ~3s)
    const hs_deadline = nowMs() + 3000;
    while (nowMs() < hs_deadline) {
        if (slen >= 2 and sbuf[0] == 0xAF) {
            r.af_greeted = true;
            std.mem.copyForwards(u8, sbuf[0 .. slen - 2], sbuf[2..slen]);
            slen -= 2;
            break;
        }
        const nr = conn.rd(sbuf[slen..]);
        if (nr == 0) break;
        if (nr < 0) continue;
        slen += @intCast(nr);
    }

    // GAMELOGON (0x68), 37 bytes — identical layout to the main path
    var gl: [37]u8 = [_]u8{0} ** 37;
    gl[0] = 0x68;
    std.mem.writeInt(u32, gl[1..5], ghash, .little);
    std.mem.writeInt(u16, gl[5..7], gtoken, .little);
    gl[7] = char_class;
    std.mem.writeInt(u32, gl[8..12], ver_byte, .little);
    std.mem.writeInt(u32, gl[12..16], 0xed5fcc50, .little);
    std.mem.writeInt(u32, gl[16..20], 0x91a519b6, .little);
    gl[20] = 0;
    @memcpy(gl[21..][0..@min(charname.len, 16)], charname[0..@min(charname.len, 16)]);
    conn.wr(&gl) catch return r;

    // read whatever comes back for read_ms; count bytes + flag 0x01/0x02
    slen = 0;
    const deadline = nowMs() + read_ms;
    while (nowMs() < deadline) {
        const nr = conn.rd(sbuf[slen..]);
        if (nr == 0) break;
        if (nr < 0) continue;
        const n: usize = @intCast(nr);
        for (sbuf[slen .. slen + n]) |b| {
            if (b == 0x01) r.saw_gameflags = true;
            if (b == 0x02) r.saw_loadsuccess = true;
        }
        r.post_logon_bytes += n;
        slen += n;
        if (slen > sbuf.len - 2048) slen = 0; // we only care about counts/flags, recycle
    }
    return r;
}

const SID_AUTH_INFO = 0x50;
const SID_AUTH_CHECK = 0x51;
const SID_PING = 0x25;

fn fourcc(s: []const u8) u32 {
    return @as(u32, s[3]) | (@as(u32, s[2]) << 8) | (@as(u32, s[1]) << 16) | (@as(u32, s[0]) << 24);
}
fn cstrAt(b: []const u8, off: usize) []const u8 {
    if (off >= b.len) return "";
    const end = std.mem.indexOfScalarPos(u8, b, off, 0) orelse b.len;
    return b[off..end];
}
fn authMeaning(r: u32) []const u8 {
    return switch (r) {
        0x000 => "PASSED — version + checksum accepted",
        0x100 => "old game version (forced patch)",
        0x101 => "invalid version",
        0x102 => "game version must be downgraded",
        0x200 => "invalid CD key  => VERSION CHECK PASSED",
        0x201 => "CD key in use   => VERSION CHECK PASSED",
        0x202 => "banned key      => VERSION CHECK PASSED",
        0x203 => "wrong product   => VERSION CHECK PASSED",
        else => if (r & 0xFF00 == 0x0100) "invalid-version variant" else "other (version likely passed)",
    };
}

// MCP_CREATEGAME (0x03) result codes.
fn createGameMeaning(r: u32) []const u8 {
    return switch (r) {
        0x00 => "created (now send JOINGAME)",
        0x1e => "invalid game name",
        0x1f => "game already exists",
        0x20 => "game servers are down",
        0x6e => "a dead hardcore character cannot create games",
        else => "failed (unknown / no GS available)",
    };
}

// MCP_JOINGAME (0x04) result codes.
fn joinGameMeaning(r: u32) []const u8 {
    return switch (r) {
        0x00 => "OK",
        0x29 => "password incorrect",
        0x2a => "game does not exist",
        0x2b => "game is full",
        0x2c => "you do not meet the level requirement",
        0x6f => "a dead hardcore character cannot join",
        0x71 => "a non-hardcore character cannot join",
        0x73 => "unable to join (LoD game from a Classic client)",
        else => "failed (unknown)",
    };
}

// S->C packet framing (size table + variable-length derivation) lives in game/packets.zig.
const scPacketSize = packets.packetSize;

var rxbuf: [16384]u8 = undefined;
var rxlen: usize = 0;

// --verbose: hexdump every packet the server sends (BNCS + MCP), matched or not.
var verbose: bool = false;
fn dumpPkt(proto: []const u8, id: u8, body: []const u8) void {
    if (!verbose) return;
    std.debug.print("  [rx {s} 0x{x:0>2}] {d} bytes\n", .{ proto, id, body.len });
    var i: usize = 0;
    while (i < body.len) : (i += 16) {
        const end = @min(i + 16, body.len);
        std.debug.print("    ", .{});
        for (body[i..end]) |b| std.debug.print("{x:0>2} ", .{b});
        var pad = end;
        while (pad < i + 16) : (pad += 1) std.debug.print("   ", .{});
        std.debug.print(" |", .{});
        for (body[i..end]) |b| std.debug.print("{c}", .{if (b >= 0x20 and b < 0x7f) b else '.'});
        std.debug.print("|\n", .{});
    }
}

// Raw hexdump (offset + hex + ascii), for unframed streams like the GS game protocol.
fn rawDump(bytes: []const u8) void {
    if (!verbose) return;
    var i: usize = 0;
    while (i < bytes.len) : (i += 16) {
        const end = @min(i + 16, bytes.len);
        std.debug.print("    {x:0>4}  ", .{i});
        for (bytes[i..end]) |b| std.debug.print("{x:0>2} ", .{b});
        var pad = end;
        while (pad < i + 16) : (pad += 1) std.debug.print("   ", .{});
        std.debug.print(" |", .{});
        for (bytes[i..end]) |b| std.debug.print("{c}", .{if (b >= 0x20 and b < 0x7f) b else '.'});
        std.debug.print("|\n", .{});
    }
}

/// Read framed BNCS packets until one with id == want; auto-echo SID_PING.
fn recvUntil(fd: Socket, want: u8, out: []u8) ![]const u8 {
    while (true) {
        while (rxlen >= 4 and rxbuf[0] == 0xFF) {
            const id = rxbuf[1];
            const plen = std.mem.readInt(u16, rxbuf[2..4], .little);
            if (plen < 4 or plen > rxbuf.len) return error.BadFrame;
            if (rxlen < plen) break; // need more bytes
            const body = rxbuf[4..plen];
            dumpPkt("BNCS", id, body);
            if (id == 0x4a or id == 0x4c) // SID_OPTIONALWORK / SID_REQUIREDWORK: a work MPQ name
                std.debug.print("[WORK 0x{x:0>2}] \"{s}\"\n", .{ id, cstrAt(body, 0) });
            if (id == SID_PING) {
                var echo: [8]u8 = .{ 0xFF, SID_PING, 8, 0, 0, 0, 0, 0 };
                @memcpy(echo[4..8], body[0..4]);
                try writeAll(fd, &echo);
                std.debug.print("  <- SID_PING, echoed cookie\n", .{});
            } else if (id == want) {
                const blen = plen - 4;
                @memcpy(out[0..blen], body);
                std.mem.copyForwards(u8, rxbuf[0 .. rxlen - plen], rxbuf[plen..rxlen]);
                rxlen -= plen;
                return out[0..blen];
            }
            std.mem.copyForwards(u8, rxbuf[0 .. rxlen - plen], rxbuf[plen..rxlen]);
            rxlen -= plen;
        }
        const got = read(fd, rxbuf[rxlen..].ptr, rxbuf.len - rxlen);
        if (got <= 0) return error.Closed;
        rxlen += @intCast(got);
    }
}

fn send(fd: Socket, id: u8, body: []const u8) !void {
    pace();
    var hdr: [4]u8 = .{ 0xFF, id, 0, 0 };
    std.mem.writeInt(u16, hdr[2..4], @intCast(body.len + 4), .little);
    try writeAll(fd, &hdr);
    try writeAll(fd, body);
}

const SID_LOGONRESPONSE2 = 0x3a;
const SID_CREATEACCOUNT2 = 0x3d;
const SID_QUERYREALMS2 = 0x40;
const SID_LOGONREALMEX = 0x3e;
const SID_ENTERCHAT = 0x0a;
const SID_GETCHANNELLIST = 0x0b;
const SID_JOINCHANNEL = 0x0c;
const SID_CHATCOMMAND = 0x0e;
const SID_CHATEVENT = 0x0f;
const SID_GETADVLISTEX = 0x09; // open-bnet public game list (peer-hosted games)
const MCP_STARTUP = 0x01;
const MCP_CHARCREATE = 0x02;
const MCP_CREATEGAME = 0x03;
const MCP_JOINGAME = 0x04;
const MCP_CHARLOGON = 0x07;
const MCP_LADDERDATA = 0x11;
const MCP_MOTD = 0x12;
const MCP_CHARLIST2 = 0x19;
const CLIENT_TOKEN: u32 = 0xCAFEBABE;

// Send a chat message / slash command (SID_CHATCOMMAND: STRING text).
fn sendChat(fd: Socket, text: []const u8) void {
    var buf: [256]u8 = undefined;
    if (text.len + 1 > buf.len) return;
    @memcpy(buf[0..text.len], text);
    buf[text.len] = 0;
    send(fd, SID_CHATCOMMAND, buf[0 .. text.len + 1]) catch {};
}

fn eidName(eid: u32) []const u8 {
    return switch (eid) {
        0x01 => "SHOWUSER", 0x02 => "JOIN", 0x03 => "LEAVE", 0x04 => "WHISPER",
        0x05 => "TALK", 0x06 => "BROADCAST", 0x07 => "CHANNEL", 0x09 => "USERFLAGS",
        0x0a => "WHISPERSENT", 0x0d => "CHANNELFULL", 0x12 => "INFO", 0x13 => "ERROR",
        0x17 => "EMOTE", else => "EID?",
    };
}

fn printChatEvent(body: []const u8) void {
    if (body.len < 28) return;
    const eid = std.mem.readInt(u32, body[0..4], .little);
    const uname = cstrAt(body, 24);
    const text = cstrAt(body, 24 + uname.len + 1);
    std.debug.print("    «{s}» {s}: {s}\n", .{ eidName(eid), uname, text });
}

// Poll the BNCS socket once (uses the current SO_RCVTIMEO), parse all complete frames,
// print chat events, auto-echo PING. Returns 0 if the peer closed, -1 on timeout, 1 on data.
fn pumpEvents(fd: Socket) i32 {
    const got = read(fd, rxbuf[rxlen..].ptr, rxbuf.len - rxlen);
    if (got == 0) return 0;
    if (got < 0) return -1;
    rxlen += @intCast(got);
    while (rxlen >= 4 and rxbuf[0] == 0xFF) {
        const id = rxbuf[1];
        const plen = std.mem.readInt(u16, rxbuf[2..4], .little);
        if (plen < 4 or plen > rxbuf.len or rxlen < plen) break;
        const body = rxbuf[4..plen];
        dumpPkt("BNCS", id, body);
        if (id == SID_PING) {
            var echo: [8]u8 = .{ 0xFF, SID_PING, 8, 0, 0, 0, 0, 0 };
            @memcpy(echo[4..8], body[0..4]);
            writeAll(fd, &echo) catch {};
        } else if (id == SID_CHATEVENT) {
            printChatEvent(body);
        }
        std.mem.copyForwards(u8, rxbuf[0 .. rxlen - plen], rxbuf[plen..rxlen]);
        rxlen -= plen;
    }
    return 1;
}

// MCP (realm/character server) framing: [u16 len incl header][u8 id][body]. Separate
// connection + buffer from BNCS (which uses the 0xFF framing).
var mrx: [16384]u8 = undefined;
var mrxlen: usize = 0;
fn mcpSend(fd: Socket, id: u8, body: []const u8) !void {
    pace();
    var hdr: [3]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], @intCast(body.len + 3), .little);
    hdr[2] = id;
    try writeAll(fd, &hdr);
    if (body.len > 0) try writeAll(fd, body);
}
fn mcpRecv(fd: Socket, want: u8, out: []u8) ![]const u8 {
    while (true) {
        while (mrxlen >= 3) {
            const plen = std.mem.readInt(u16, mrx[0..2], .little);
            if (plen < 3 or plen > mrx.len) return error.BadFrame;
            if (mrxlen < plen) break;
            const id = mrx[2];
            const blen = plen - 3;
            dumpPkt("MCP", id, mrx[3..plen]);
            if (id == want) {
                @memcpy(out[0..blen], mrx[3..plen]);
                std.mem.copyForwards(u8, mrx[0 .. mrxlen - plen], mrx[plen..mrxlen]);
                mrxlen -= plen;
                return out[0..blen];
            }
            std.mem.copyForwards(u8, mrx[0 .. mrxlen - plen], mrx[plen..mrxlen]);
            mrxlen -= plen;
        }
        const got = read(fd, mrx[mrxlen..].ptr, mrx.len - mrxlen);
        if (got <= 0) return error.Closed;
        mrxlen += @intCast(got);
    }
}

fn lower(s: []const u8, buf: []u8) []const u8 {
    for (s, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..s.len];
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// `clientless replay <file>` — decode a captured S->C stream offline (no server). The file may
// be raw bytes or a hexdump ("ae 12 00 ..." / "0xAE,0x12" / one long hex blob). Everything runs
// through the same framing + world model as a live join, then prints a world snapshot.
fn replay(gpa: std.mem.Allocator, path_opt: ?[]const u8) !void {
    const path = path_opt orelse {
        std.debug.print("usage: clientless replay <capture-file>\n", .{});
        return;
    };
    var pathz: [4096]u8 = undefined;
    if (path.len >= pathz.len) {
        std.debug.print("replay: path too long\n", .{});
        return;
    }
    @memcpy(pathz[0..path.len], path);
    pathz[path.len] = 0;
    const fd = open(@ptrCast(&pathz), 0); // O_RDONLY
    if (fd < 0) {
        std.debug.print("replay: cannot open {s}\n", .{path});
        return;
    }
    defer _ = close(fd);
    const cap: usize = 32 << 20;
    const data = try gpa.alloc(u8, cap);
    defer gpa.free(data);
    var total: usize = 0;
    while (total < cap) {
        const r = read(fd, data[total..].ptr, cap - total);
        if (r <= 0) break;
        total += @intCast(r);
    }
    const contents = data[0..total];

    // Heuristic: pure hex/whitespace text -> parse as a hexdump; otherwise treat as raw bytes.
    var looks_hex = contents.len > 0;
    for (contents) |b| {
        if (hexVal(b) == null and b != ' ' and b != '\t' and b != '\n' and b != '\r' and b != ':' and b != ',' and b != 'x' and b != 'X') {
            looks_hex = false;
            break;
        }
    }

    var bytes: []const u8 = contents;
    var decoded: []u8 = &[_]u8{};
    if (looks_hex) {
        decoded = try gpa.alloc(u8, contents.len / 2 + 1);
        var n: usize = 0;
        var hi: ?u8 = null;
        for (contents) |c| {
            const v = hexVal(c);
            if (v) |lo| {
                if (hi) |h| {
                    decoded[n] = (h << 4) | lo;
                    n += 1;
                    hi = null;
                } else hi = lo;
            } else hi = null; // any separator (incl. the 'x' in 0x) resets the nibble pair
        }
        bytes = decoded[0..n];
    }
    defer if (decoded.len > 0) gpa.free(decoded);

    std.debug.print("replay: {s} ({d} bytes {s})\n", .{ path, bytes.len, if (looks_hex) "from hex" else "raw" });
    var world = world_mod.World.init(gpa);
    world.verbose = true;
    defer world.deinit();
    const count = feedStream(&world, bytes, true);
    std.debug.print("\nreplayed {d} packets\n", .{count});
    world.dumpSummary();
}

// Frame a COMPLETE buffer of S->C bytes and apply every packet, decompressing 0xAE containers.
// Shares the framing rules with the live GS loop; used by `replay`. Returns the packet count.
fn feedStream(world: *world_mod.World, bytes: []const u8, log: bool) usize {
    var off: usize = 0;
    var count: usize = 0;
    while (off < bytes.len) {
        const n = scPacketSize(bytes[off..]) orelse break; // truncated tail
        if (n == 0) { // invalid opcode -> resync a byte
            off += 1;
            continue;
        }
        const id = bytes[off];
        if (log) {
            var nb: [8]u8 = undefined;
            std.debug.print("<- {s} 0x{x:0>2} ({d} bytes)\n", .{ packets.label(id, &nb), id, n });
        }
        if (id == 0xAE and n > 3) {
            var dbuf: [16384]u8 = undefined;
            if (huffman.decompress(bytes[off + 3 .. off + n], &dbuf)) |dlen| {
                var io: usize = 0;
                while (io < dlen) {
                    const isz = scPacketSize(dbuf[io..dlen]) orelse break;
                    if (isz == 0) break;
                    if (log) {
                        var inb: [8]u8 = undefined;
                        std.debug.print("  [inner] {s} 0x{x:0>2} ({d} bytes)\n", .{ packets.label(dbuf[io], &inb), dbuf[io], isz });
                    }
                    world.apply(dbuf[io .. io + isz]);
                    io += isz;
                }
            }
        } else {
            world.apply(bytes[off .. off + n]);
        }
        count += 1;
        off += n;
    }
    return count;
}

pub fn main(init: std.process.Init.Minimal) !void {
    const gpa = std.heap.page_allocator;

    // `clientless bnftp <args>` -> hand off to the BNFTP file client subcommand.
    {
        var peek = std.process.Args.Iterator.init(init.args);
        _ = peek.next(); // argv[0]
        if (peek.next()) |sub| {
            if (std.mem.eql(u8, sub, "bnftp")) return bnftp.run(init);
            if (std.mem.eql(u8, sub, "replay")) return replay(gpa, peek.next());
        }
    }

    var args = std.process.Args.Iterator.init(init.args);
    _ = args.next();
    var host: ?[]const u8 = null;
    var product: []const u8 = "D2XP";
    var game_ver: []const u8 = "1.14.3.71";
    var sig_ok: u8 = 1;
    var keys_arg: ?[]const u8 = null; // "KEY1,KEY2" (26-char each)
    var login_arg: ?[]const u8 = null; // "account:password"
    var create_arg: ?[]const u8 = null; // "account:password" to register first
    var channel_arg: []const u8 = "Diablo II"; // channel to join
    var say_arg: ?[]const u8 = null; // chat message to send after joining
    var kick_arg: ?[]const u8 = null; // user to /kick after joining
    var listen_sec: u32 = 0; // stay in chat reading events for N seconds (chat-session mode)
    var delay_sec: u32 = 0; // wait N seconds after joining before say/kick (2-client ordering)
    var game_arg: ?[]const u8 = null; // --game <name>: create+join the game and enter it on the GS
    var gs_port: u16 = 4000; // GS game port (qqserver public port)
    var gs_tls = false; // --gs-tls: wrap the GS leg in TLS (Blizzard's :443 D2GS-over-TLS farm)
    var gs_host: ?[]const u8 = null; // --gs-host: override the GS IP (still use JOINGAME token/hash)
    var gs_sni: []const u8 = GsSni; // --gs-sni: TLS SNI / cert hostname for the GS leg
    var gs_gw = false; // --gs-gw: TLS to the PAIRED gateway IP (backend a.b.C.d -> a.b.(C+1).d)
    var gs_pin: ?[]const u8 = null; // --gs-pin: only proceed if the GS IP's last octet is in this list
    var gs_brute: ?[]const u8 = null; // --gs-brute: fire this game's token at every 201.<oct>:443 gateway
    var gs_emit = false; // --emit-join: print JOINEMIT token/hash line and exit (for external bruteforce)
    var ver_byte: u8 = 0x0e; // GAMELOGON nVerByte — GET_GameVersion() returns 0xe (14) for 1.14d
    var bnet_port: u16 = 6112; // BNCS port to connect to (--port)
    var force_checkrev = false; // --force-checkrev: respond even if the MPQ isn't the one we implement
    var pos: usize = 0;
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--sig0")) {
            sig_ok = 0;
        } else if (std.mem.eql(u8, a, "--keys")) {
            keys_arg = args.next();
        } else if (std.mem.eql(u8, a, "--login")) {
            login_arg = args.next();
        } else if (std.mem.eql(u8, a, "--create")) {
            create_arg = args.next();
        } else if (std.mem.eql(u8, a, "--channel")) {
            channel_arg = args.next() orelse channel_arg;
        } else if (std.mem.eql(u8, a, "--say")) {
            say_arg = args.next();
        } else if (std.mem.eql(u8, a, "--kick")) {
            kick_arg = args.next();
        } else if (std.mem.eql(u8, a, "--listen")) {
            listen_sec = std.fmt.parseInt(u32, args.next() orelse "0", 10) catch 0;
        } else if (std.mem.eql(u8, a, "--delay")) {
            delay_sec = std.fmt.parseInt(u32, args.next() orelse "0", 10) catch 0;
        } else if (std.mem.eql(u8, a, "--game")) {
            game_arg = args.next();
        } else if (std.mem.eql(u8, a, "--gs-port")) {
            gs_port = std.fmt.parseInt(u16, args.next() orelse "4000", 10) catch 4000;
        } else if (std.mem.eql(u8, a, "--gs-tls")) {
            gs_tls = true;
            if (gs_port == 4000) gs_port = 443; // sensible default: TLS farm listens on 443
        } else if (std.mem.eql(u8, a, "--gs-host")) {
            gs_host = args.next();
        } else if (std.mem.eql(u8, a, "--gs-sni")) {
            gs_sni = args.next() orelse gs_sni;
        } else if (std.mem.eql(u8, a, "--gs-gw")) {
            gs_gw = true;
        } else if (std.mem.eql(u8, a, "--gs-pin")) {
            gs_pin = args.next();
        } else if (std.mem.eql(u8, a, "--gs-brute")) {
            gs_brute = args.next();
        } else if (std.mem.eql(u8, a, "--emit-join")) {
            gs_emit = true;
        } else if (std.mem.eql(u8, a, "--verbyte")) {
            ver_byte = std.fmt.parseInt(u8, args.next() orelse "0", 10) catch 0;
        } else if (std.mem.eql(u8, a, "--port")) {
            bnet_port = std.fmt.parseInt(u16, args.next() orelse "6112", 10) catch 6112;
        } else if (std.mem.eql(u8, a, "--delay")) {
            step_delay_ms = std.fmt.parseInt(u64, args.next() orelse "0", 10) catch 0;
        } else if (std.mem.eql(u8, a, "--force-checkrev")) {
            force_checkrev = true;
        } else if (std.mem.eql(u8, a, "--verbose")) {
            verbose = true;
        } else if (!std.mem.startsWith(u8, a, "--")) {
            switch (pos) {
                0 => host = a,
                1 => product = a,
                2 => game_ver = a,
                else => {},
            }
            pos += 1;
        }
    }
    const h = host orelse {
        std.debug.print(
            \\clientless — a pure-Zig Diablo II 1.14d Battle.net client (no game binary)
            \\
            \\usage:
            \\  clientless <host> [product] [version] [options]   BNCS / MCP / chat / game
            \\  clientless bnftp [options] <host> [product] [file]  BNFTP file client
            \\
            \\  product              D2DV (classic) | D2XP (expansion, default)
            \\  version              client version string (default 1.14.3.71)
            \\
            \\auth:
            \\  --keys K1[,K2]       26-char CD-key(s); omit on a permissive realm
            \\  --login acct:pass    log in to an existing account
            \\  --create acct:pass   create the account, then log in
            \\  --force-checkrev     respond even if the version-check MPQ isn't CheckRevision.mpq
            \\  --sig0               report sigOk=0 in CheckRevision
            \\
            \\game / chat:
            \\  --game <name>        create + join the game and enter it on the GS
            \\  --gs-port <n>        GS game port (default 4000; 443 when --gs-tls)
            \\  --gs-tls             join the GS over TLS (Blizzard's :443 D2GS-over-TLS farm)
            \\  --gs-host <ip>       override the GS IP (keep JOINGAME token/hash; e.g. a :443 gateway)
            \\  --gs-sni <name>      TLS SNI/cert host for --gs-tls (default asia.diablo2.blizzard.com)
            \\  --gs-gw              TLS to the paired gateway IP (backend a.b.C.d -> a.b.C+1.d)
            \\  --gs-pin <octets>    only proceed if GS IP's last octet is in this comma list (else exit 2)
            \\  --gs-brute <octets>  fire this game's token at every 201.<oct>:443 gateway; report routers
            \\  --channel <name>     chat channel to join (default "Diablo II")
            \\  --say <text>         send a chat message after entering chat
            \\  --kick <user>        /kick a user (needs channel-operator)
            \\  --listen <sec>       stay in chat reading events for N seconds
            \\
            \\connection / debug:
            \\  --port <n>           BNCS port (default 6112)
            \\  --verbyte <n>        GAMELOGON version byte (default 14 = 1.14d)
            \\  --delay <ms>         pause before each step (gentler pacing; e.g. 500)
            \\  --verbose            hexdump all BNCS + MCP traffic + GS packets
            \\
            \\examples:
            \\  # version check only (no keys/account)
            \\  clientless useast.battle.net
            \\  # full session on your own realm: create char, chat, ladder
            \\  clientless realm.example.com D2XP 1.14.3.71 --login me:pw --listen 20
            \\  # create the account first, then create + enter a game
            \\  clientless realm.example.com D2XP 1.14.3.71 --create me:pw --game MyGame
            \\  # two clients chatting (op kicks the other)
            \\  clientless realm.example.com --login op:pw --channel ops --kick rude
            \\  # live Battle.net with real CD-keys (your account, your risk)
            \\  clientless useast.battle.net D2XP 1.14.3.71 --keys K1,K2 --login acct:pw --game MyGame
            \\  # BNFTP: fetch a file's size, then download it
            \\  clientless bnftp --head useast.battle.net D2XP CheckRevision.mpq
            \\  clientless bnftp --out-dir . useast.battle.net D2XP CheckRevision.mpq
            \\
        , .{});
        return;
    };

    std.debug.print("== {s}:{d}  product={s}  gameVer={s}  sigOk={d} ==\n", .{ h, bnet_port, product, game_ver, sig_ok });
    const fd = try connectResolved(gpa, h, bnet_port);
    defer _ = close(fd);
    try writeAll(fd, &[_]u8{0x01}); // protocol selector: BNCS

    // ── SID_AUTH_INFO ──
    var body: [128]u8 = undefined;
    var w: usize = 0;
    for ([_]u32{ 0, fourcc("IX86"), fourcc(product), 0x0E, 0, 0, 0, 0, 0 }) |v| {
        std.mem.writeInt(u32, body[w..][0..4], v, .little);
        w += 4;
    }
    for ("USA\x00United States\x00") |c| {
        body[w] = c;
        w += 1;
    }
    try send(fd, SID_AUTH_INFO, body[0..w]);

    var aibuf: [4096]u8 = undefined;
    const ai = try recvUntil(fd, SID_AUTH_INFO, &aibuf);
    if (ai.len < 20) return error.ShortAuthInfo;
    const stoken = std.mem.readInt(u32, ai[4..8], .little);
    const mpq = cstrAt(ai, 20);
    const challenge = cstrAt(ai, 20 + mpq.len + 1);
    std.debug.print("\n[AUTH_INFO] serverToken=0x{x:0>8}  mpq=\"{s}\"  challenge=\"{s}\"\n", .{ stoken, mpq, challenge });

    // ── compute the CheckRevision response. Modern bnet sends a base64 challenge; classic
    //    realmd/pvpgn sends the legacy "A=1 B=1 C=1 …" formula (computed over the game files,
    //    which a clientless tool doesn't ship). Permissive realms accept any AUTH_CHECK, so
    //    for the classic formula we send placeholder version/hash. ──
    var full_buf: [64]u8 = undefined;
    var exe_version: u32 = 0;
    var exe_hash: u32 = undefined;
    var exe_info: []const u8 = undefined;
    if (std.mem.indexOfScalar(u8, challenge, ' ') != null or std.mem.startsWith(u8, challenge, "A=")) {
        exe_version = 0x01000001;
        exe_hash = 0xdeadbeef;
        exe_info = "";
        std.debug.print("[checkrev] CLASSIC challenge -> placeholder exeHash=0x{x:0>8} (permissive realm)\n", .{exe_hash});
    } else {
        // Our checkrev_core implements the 1.14d CheckRevision.mpq algorithm specifically.
        // A different MPQ means a different hashing routine we don't replicate, so our
        // response would be wrong — bail rather than send a bogus AUTH_CHECK (which could
        // flag the account). --force-checkrev sends it anyway (e.g. probing a new server).
        const EXPECTED_MPQ = "CheckRevision.mpq";
        if (!std.mem.eql(u8, mpq, EXPECTED_MPQ)) {
            std.debug.print("[checkrev] UNEXPECTED MPQ \"{s}\" — we only implement \"{s}\". " ++
                "Not sending a (likely wrong) response. Use --force-checkrev to override.\n", .{ mpq, EXPECTED_MPQ });
            if (!force_checkrev) return error.UnexpectedCheckRevisionMPQ;
        }
        // modern split: first 4 base64 bytes -> EXE Hash (u32 LE); rest -> EXE Info string
        const full = core.response(challenge, game_ver, sig_ok, &full_buf) orelse return error.ShortChallenge;
        exe_hash = std.mem.readInt(u32, full[0..4], .little);
        exe_info = full[4..];
        std.debug.print("[checkrev] response=\"{s}\"  -> exeHash=0x{x:0>8}  exeInfo=\"{s}\"\n", .{ full, exe_hash, exe_info });
    }

    // ── SID_AUTH_CHECK (with real CD-key blocks, computed clientless) ──
    var cb: [512]u8 = undefined;
    var cw: usize = 0;
    var nkeys: u32 = 0;
    var keyit = std.mem.tokenizeScalar(u8, keys_arg orelse "", ',');
    // header (we backfill numKeys after counting): clientToken, exeVersion(0), exeHash, numKeys, spawn(0)
    const hdr_keys_off = 12; // offset of the numKeys field in the header
    std.mem.writeInt(u32, cb[0..4], CLIENT_TOKEN, .little);
    std.mem.writeInt(u32, cb[4..8], exe_version, .little);
    std.mem.writeInt(u32, cb[8..12], exe_hash, .little);
    std.mem.writeInt(u32, cb[16..20], 0, .little); // spawn
    cw = 20;
    while (keyit.next()) |k| {
        const blk = cdkey.keyBlock26(k, CLIENT_TOKEN, stoken) orelse {
            std.debug.print("[keys] bad 26-char key: {s}\n", .{k});
            return;
        };
        var wire: [36]u8 = undefined;
        blk.writeWire(&wire);
        @memcpy(cb[cw .. cw + 36], &wire);
        cw += 36;
        nkeys += 1;
        std.debug.print("[keys] key[{d}] product=0x{x:0>8} public=0x{x:0>8}\n", .{ nkeys - 1, blk.product, blk.public });
    }
    std.mem.writeInt(u32, cb[hdr_keys_off..][0..4], nkeys, .little);
    @memcpy(cb[cw .. cw + exe_info.len], exe_info); // EXE Information string
    cw += exe_info.len;
    cb[cw] = 0;
    cw += 1;
    for ("probe\x00") |c| { // CD-key owner
        cb[cw] = c;
        cw += 1;
    }
    try send(fd, SID_AUTH_CHECK, cb[0..cw]);

    var acbuf: [1024]u8 = undefined;
    const ac = recvUntil(fd, SID_AUTH_CHECK, &acbuf) catch |e| {
        std.debug.print("\n[AUTH_CHECK] no reply ({s}) — server dropped the packet (malformed/keyless).\n", .{@errorName(e)});
        return;
    };
    if (ac.len < 4) return error.ShortAuthCheck;
    const result = std.mem.readInt(u32, ac[0..4], .little);
    std.debug.print("\n[AUTH_CHECK] result=0x{x:0>4}  info=\"{s}\"  => {s}\n", .{ result, cstrAt(ac, 4), authMeaning(result) });

    // ── SID_CREATEACCOUNT2 (register — single broken-SHA-1 of the password) ──
    if (create_arg) |ca| {
        const sep = std.mem.indexOfScalar(u8, ca, ':') orelse ca.len;
        const acct = ca[0..sep];
        const pass = if (sep < ca.len) ca[sep + 1 ..] else "";
        var lb: [64]u8 = undefined;
        const pwhash = xsha1.xsha1(lower(pass, &lb)); // single hash for CREATE (login uses double)
        var nb: [320]u8 = undefined;
        @memcpy(nb[0..20], &pwhash);
        @memcpy(nb[20 .. 20 + acct.len], acct);
        nb[20 + acct.len] = 0;
        try send(fd, SID_CREATEACCOUNT2, nb[0 .. 20 + acct.len + 1]);
        var nrbuf: [256]u8 = undefined;
        const nr = try recvUntil(fd, SID_CREATEACCOUNT2, &nrbuf);
        const st = if (nr.len >= 4) std.mem.readInt(u32, nr[0..4], .little) else 0xffffffff;
        std.debug.print("[CREATEACCOUNT2] account=\"{s}\" status={d}  => {s}\n", .{ acct, st, if (st == 0) "created" else "failed/exists" });
        if (login_arg == null) login_arg = create_arg; // auto-login as the freshly-created account
    }

    // ── SID_LOGONRESPONSE2 (OLS account login) ──
    if (login_arg) |la| {
        const sep = std.mem.indexOfScalar(u8, la, ':') orelse la.len;
        const acct = la[0..sep];
        const pass = if (sep < la.len) la[sep + 1 ..] else "";
        var lb: [64]u8 = undefined;
        const inner = xsha1.xsha1(lower(pass, &lb)); // xsha1(lowercase(password))
        const pwhash = xsha1.doubleHash(CLIENT_TOKEN, stoken, inner);
        var pb: [320]u8 = undefined;
        std.mem.writeInt(u32, pb[0..4], CLIENT_TOKEN, .little);
        std.mem.writeInt(u32, pb[4..8], stoken, .little);
        @memcpy(pb[8..28], &pwhash);
        @memcpy(pb[28 .. 28 + acct.len], acct);
        pb[28 + acct.len] = 0;
        try send(fd, SID_LOGONRESPONSE2, pb[0 .. 28 + acct.len + 1]);
        var lbuf: [256]u8 = undefined;
        const lr = try recvUntil(fd, SID_LOGONRESPONSE2, &lbuf);
        const lres = if (lr.len >= 4) std.mem.readInt(u32, lr[0..4], .little) else 0xffffffff;
        const meaning = switch (lres) {
            0 => "OK — account+password accepted",
            1 => "no such account",
            2 => "incorrect password",
            else => "other",
        };
        std.debug.print("[LOGONRESPONSE2] account=\"{s}\" result={d}  => {s}\n", .{ acct, lres, meaning });
        if (lres != 0) return; // can't query realms without a logged-in account

        // ── SID_QUERYREALMS2 — the realm list (EMPTY body; real bnet closes on a non-empty one) ──
        try send(fd, SID_QUERYREALMS2, &[_]u8{});
        var qbuf: [4096]u8 = undefined;
        const qr = try recvUntil(fd, SID_QUERYREALMS2, &qbuf);
        var first_realm: []const u8 = "";
        if (qr.len >= 8) {
            const count = std.mem.readInt(u32, qr[4..8], .little);
            std.debug.print("[QUERYREALMS2] {d} realm(s):\n", .{count});
            var off: usize = 8;
            var n: u32 = 0;
            while (n < count and off + 4 <= qr.len) : (n += 1) {
                off += 4; // per-realm unknown dword
                const title = cstrAt(qr, off);
                off += title.len + 1;
                const desc = cstrAt(qr, off);
                off += desc.len + 1;
                if (n == 0) first_realm = title;
                std.debug.print("  - \"{s}\"  ({s})\n", .{ title, desc });
            }
        }
        if (first_realm.len == 0) return;

        // ── SID_LOGONREALMEX — log on to the first realm (closed-bnet realm password = "password") ──
        const realm_pw = xsha1.doubleHash(CLIENT_TOKEN, stoken, xsha1.xsha1("password"));
        var rb: [128]u8 = undefined;
        std.mem.writeInt(u32, rb[0..4], CLIENT_TOKEN, .little);
        @memcpy(rb[4..24], &realm_pw);
        @memcpy(rb[24 .. 24 + first_realm.len], first_realm);
        rb[24 + first_realm.len] = 0;
        try send(fd, SID_LOGONREALMEX, rb[0 .. 24 + first_realm.len + 1]);
        var rrbuf: [256]u8 = undefined;
        const rr = try recvUntil(fd, SID_LOGONREALMEX, &rrbuf);
        // Real bnet's success layout differs from realmd's, so success is read from the
        // reply length, not a status DWORD. (Hexdump only in --verbose.)
        if (verbose) {
            std.debug.print("[LOGONREALMEX] realm=\"{s}\" reply {d} bytes:\n", .{ first_realm, rr.len });
            var hi: usize = 0;
            while (hi < rr.len) : (hi += 1) std.debug.print("{x:0>2} ", .{rr[hi]});
            std.debug.print("\n", .{});
        }
        // Short reply (~8 bytes = cookie+status) is a real failure; a long reply carries the
        // MCP handoff (cookie, status, chunk1, ip, port, chunk2, unique name) = success.
        if (rr.len < 30) {
            const status = if (rr.len >= 8) std.mem.readInt(u32, rr[4..8], .little) else 0xffffffff;
            std.debug.print("[LOGONREALMEX] realm=\"{s}\" => FAILED (status=0x{x})\n", .{ first_realm, status });
            return;
        }
        std.debug.print("[LOGONREALMEX] realm=\"{s}\" => OK ({d}-byte MCP handoff)\n", .{ first_realm, rr.len });

        // ── MCP (realm/character server) — connect to the addr the realm gave us ──
        const ip4 = rr[16..20];
        const mport = std.mem.readInt(u16, rr[20..22], .big);
        var ipstr: [20]u8 = undefined;
        const ipfmt = std.fmt.bufPrint(&ipstr, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch return;
        // Real bnet returns the d2cs server's PRIVATE (NATed) IP — unreachable externally.
        // Fall back to the gateway host (the addr we connected to), in case it proxies MCP.
        const priv = ip4[0] == 10 or (ip4[0] == 192 and ip4[1] == 168) or (ip4[0] == 172 and ip4[1] >= 16 and ip4[1] <= 31) or ip4[0] == 127 or ip4[0] == 0;
        const ips = if (priv) (host orelse ipfmt) else ipfmt;
        if (priv)
            std.debug.print("[MCP] realm returned PRIVATE ip {s}:{d} (Blizzard NAT) -> retrying via gateway {s}:{d}\n", .{ ipfmt, mport, ips, mport })
        else
            std.debug.print("[MCP] connecting to {s}:{d}\n", .{ ips, mport });
        const mfd = connectResolved(gpa, ips, mport) catch {
            std.debug.print("[MCP] connect failed\n", .{});
            return;
        };
        defer _ = close(mfd);
        mrxlen = 0;
        try writeAll(mfd, &[_]u8{0x01}); // MCP protocol selector

        // MCP_STARTUP: forward cookie+status+chunk1(8)+chunk2(48) from the realm reply
        var sb: [64]u8 = [_]u8{0} ** 64;
        @memcpy(sb[0..16], rr[0..16]);
        if (rr.len >= 72) @memcpy(sb[16..64], rr[24..72]);
        try mcpSend(mfd, MCP_STARTUP, &sb);
        var mb: [8192]u8 = undefined;
        const sr = mcpRecv(mfd, MCP_STARTUP, &mb) catch {
            std.debug.print("[MCP_STARTUP] no MCP reply from {s}:{d} — d2cs is unreachable (internal-only; realm logon succeeded but the char/game server is NATed)\n", .{ ips, mport });
            return;
        };
        const sres = if (sr.len >= 4) std.mem.readInt(u32, sr[0..4], .little) else 0xffffffff;
        std.debug.print("[MCP_STARTUP] result=0x{x}  => {s}\n", .{ sres, if (sres == 0) "session accepted (in the realm)" else "rejected" });
        if (sres != 0) return;

        // NOTE: the real 1.14d client does NOT send MCP_MOTD (0x12) here — its MCP
        // sequence is STARTUP -> CHARLIST2 -> CHARLOGON (captured via REALMD_TRACE).
        // The chat-screen MOTD arrives over BNCS SID_NEWS_INFO instead. Sending MCP_MOTD
        // derails real bnet's MCP (it goes silent after STARTUP).

        // MCP_CHARLIST2 — the account's characters on this realm
        var clreq: [4]u8 = undefined;
        std.mem.writeInt(u32, &clreq, 8, .little);
        try mcpSend(mfd, MCP_CHARLIST2, &clreq);
        const cl = mcpRecv(mfd, MCP_CHARLIST2, &mb) catch &[_]u8{};
        var cname_buf: [32]u8 = undefined;
        var cname_len: usize = 0;
        if (cl.len >= 8) {
            const total = std.mem.readInt(u32, cl[2..6], .little);
            const ret = std.mem.readInt(u16, cl[6..8], .little);
            std.debug.print("[MCP_CHARLIST2] total={d} returned={d}\n", .{ total, ret });
            var off2: usize = 8;
            var ci: usize = 0;
            while (ci < ret and off2 + 4 < cl.len) : (ci += 1) {
                off2 += 4; // expiry
                const name = cstrAt(cl, off2);
                off2 += name.len + 1;
                const stat = cstrAt(cl, off2);
                off2 += stat.len + 1;
                std.debug.print("  - char \"{s}\"\n", .{name});
                if (cname_len == 0 and name.len > 0 and name.len < cname_buf.len) {
                    @memcpy(cname_buf[0..name.len], name);
                    cname_len = name.len;
                }
            }
        }

        // ── MCP_CHARCREATE — make a character if the account has none ──
        if (cname_len == 0) {
            const newname = "Clientella"; // <=15 chars
            var ccb: [64]u8 = undefined;
            std.mem.writeInt(u32, ccb[0..4], 1, .little); // class 1 = Sorceress
            std.mem.writeInt(u16, ccb[4..6], 0x20, .little); // status: 0x20 = expansion (LoD), softcore
            @memcpy(ccb[6 .. 6 + newname.len], newname);
            ccb[6 + newname.len] = 0;
            try mcpSend(mfd, MCP_CHARCREATE, ccb[0 .. 7 + newname.len]);
            const ccr = mcpRecv(mfd, MCP_CHARCREATE, &mb) catch &[_]u8{};
            const ccres = if (ccr.len >= 4) std.mem.readInt(u32, ccr[0..4], .little) else 0xffffffff;
            std.debug.print("[MCP_CHARCREATE] \"{s}\" class=Sorceress(exp) result=0x{x}  => {s}\n", .{ newname, ccres, if (ccres == 0) "created" else "failed" });
            if (ccres == 0) {
                @memcpy(cname_buf[0..newname.len], newname);
                cname_len = newname.len;
            }
        }
        if (cname_len == 0) return;
        const charname = cname_buf[0..cname_len];

        // ── MCP_CHARLOGON — select the character ──
        var clb: [40]u8 = undefined;
        @memcpy(clb[0..cname_len], charname);
        clb[cname_len] = 0;
        try mcpSend(mfd, MCP_CHARLOGON, clb[0 .. cname_len + 1]);
        const clr = mcpRecv(mfd, MCP_CHARLOGON, &mb) catch &[_]u8{};
        const clres = if (clr.len >= 4) std.mem.readInt(u32, clr[0..4], .little) else 0xffffffff;
        std.debug.print("[MCP_CHARLOGON] \"{s}\" result=0x{x}  => {s}\n", .{ charname, clres, if (clres == 0) "logged onto char" else "failed" });

        // ── enter a GAME on the GS (clientless): CREATEGAME -> JOINGAME -> connect GS ->
        //    GAMELOGON(0x68) -> JOINGAME(0x6b) -> read the world stream. Real GS only. ──
        if (game_arg) |gname| {
            // MCP_CREATEGAME (0x03): reqid, flags(u32), unk(1), playerDiff, maxPlayers, name, pass, desc
            var cgb: [128]u8 = undefined;
            std.mem.writeInt(u16, cgb[0..2], 1, .little);
            std.mem.writeInt(u32, cgb[2..6], 0, .little); // flags: normal difficulty
            cgb[6] = 1;
            cgb[7] = 0;
            cgb[8] = 8;
            var co: usize = 9;
            @memcpy(cgb[co..][0..gname.len], gname);
            co += gname.len;
            cgb[co] = 0;
            co += 1;
            cgb[co] = 0;
            co += 1; // pass ""
            cgb[co] = 'd';
            cgb[co + 1] = 0;
            co += 2; // desc "d"
            try mcpSend(mfd, MCP_CREATEGAME, cgb[0..co]);
            const cgr = mcpRecv(mfd, MCP_CREATEGAME, &mb) catch &[_]u8{};
            // reply: u16 reqid, u16 token, u16 unk, u32 result
            const cg_token = if (cgr.len >= 4) std.mem.readInt(u16, cgr[2..4], .little) else 0;
            const cg_result = if (cgr.len >= 10) std.mem.readInt(u32, cgr[6..10], .little) else 0xffffffff;
            std.debug.print("[MCP_CREATEGAME] \"{s}\" token=0x{x} result=0x{x}  => {s}\n", .{ gname, cg_token, cg_result, createGameMeaning(cg_result) });
            // 0x1f = "game already exists" (e.g. left over from a prior run): fall through and
            // JOIN it instead of bailing. Any other non-zero create result is fatal.
            if (cg_result != 0 and cg_result != 0x1f) return;
            if (cg_result == 0x1f) std.debug.print("[MCP_CREATEGAME] game exists -> joining it\n", .{});

            // MCP_JOINGAME (0x04): reqid, name, pass
            var jgb: [64]u8 = undefined;
            std.mem.writeInt(u16, jgb[0..2], 2, .little);
            var jo: usize = 2;
            @memcpy(jgb[jo..][0..gname.len], gname);
            jo += gname.len;
            jgb[jo] = 0;
            jo += 1;
            jgb[jo] = 0;
            jo += 1; // pass ""
            try mcpSend(mfd, MCP_JOINGAME, jgb[0..jo]);
            const jgr = mcpRecv(mfd, MCP_JOINGAME, &mb) catch &[_]u8{};
            if (jgr.len < 18) {
                std.debug.print("[MCP_JOINGAME] short reply ({d} B)\n", .{jgr.len});
                return;
            }
            const gtoken = std.mem.readInt(u16, jgr[2..4], .little);
            const gsip = jgr[6..10];
            const ghash = std.mem.readInt(u32, jgr[10..14], .little);
            const jresult = std.mem.readInt(u32, jgr[14..18], .little);
            var gsipbuf: [20]u8 = undefined;
            const gsips = std.fmt.bufPrint(&gsipbuf, "{d}.{d}.{d}.{d}", .{ gsip[0], gsip[1], gsip[2], gsip[3] }) catch return;
            std.debug.print("[MCP_JOINGAME] token=0x{x} gs={s}:{d} hash=0x{x} result=0x{x}  => {s}\n", .{ gtoken, gsips, gs_port, ghash, jresult, joinGameMeaning(jresult) });
            if (jresult != 0) return;

            // --emit-join: print a machine-readable line with the fresh token/hash and exit, so an
            // external parallel bruteforcer can fire it at many gateways inside the token window.
            if (gs_emit) {
                std.debug.print("JOINEMIT gsip={s} token={d} hash={d} char={s} verbyte={d}\n", .{ gsips, gtoken, ghash, charname, ver_byte });
                return;
            }

            // --gs-brute: fire THIS game's token/hash at every 158.115.201.<oct>:443 gateway and
            // report which (if any) actually streams the game back — the definitive test of whether
            // any TLS gateway routes a game our d2cs assigned to a :4000 backend.
            if (gs_brute) |octets| {
                var pre = std.mem.splitScalar(u8, gsips, '.');
                const p0 = pre.next() orelse "158";
                const p1 = pre.next() orelse "115";
                std.debug.print("[brute] game on {s}, token=0x{x} hash=0x{x} — sweeping {s}.{s}.201.x:443\n", .{ gsips, gtoken, ghash, p0, p1 });
                var any = false;
                var oit = std.mem.splitScalar(u8, octets, ',');
                while (oit.next()) |tok| {
                    if (tok.len == 0) continue;
                    var hb: [21]u8 = undefined;
                    const ghost = std.fmt.bufPrint(&hb, "{s}.{s}.201.{s}", .{ p0, p1, tok }) catch continue;
                    const res = probeGateway(gpa, ghost, 443, true, gs_sni, ghash, gtoken, 1, ver_byte, charname, 2000);
                    if (res.post_logon_bytes > 0 or res.saw_loadsuccess) {
                        any = true;
                        std.debug.print("[brute] {s}:443  *** ROUTED *** af={} post-logon={d}B gameflags={} loadsuccess={}\n", .{ ghost, res.af_greeted, res.post_logon_bytes, res.saw_gameflags, res.saw_loadsuccess });
                    } else if (res.handshook) {
                        std.debug.print("[brute] {s}:443  tls-ok af={} but SILENT after GAMELOGON\n", .{ ghost, res.af_greeted });
                    } else if (res.connected) {
                        std.debug.print("[brute] {s}:443  connected but TLS failed\n", .{ghost});
                    } else {
                        std.debug.print("[brute] {s}:443  no connect\n", .{ghost});
                    }
                }
                std.debug.print("[brute] done — {s}\n", .{if (any) "at least one gateway ROUTED the game" else "NO gateway routed the game (TLS pool is separate from the :4000 backends)"});
                return;
            }

            // Connect to the GS game port (qqserver) and play the entry sequence. --gs-host can
            // redirect to an alternate endpoint (e.g. the :443 TLS gateway) while still using the
            // token/hash this JOINGAME minted — to test whether that endpoint routes to our game.
            // --gs-pin: only proceed if the GS landed on a backend whose paired gateway is open
            // (the matched-octet set from scanning). Otherwise bail with code 2 so a shell loop
            // can retry createGame until it lands on a host that actually has a :443 gateway.
            if (gs_pin) |pinlist| {
                var oit = std.mem.splitScalar(u8, gsips, '.');
                _ = oit.next();
                _ = oit.next();
                _ = oit.next();
                const last_oct = oit.next() orelse "";
                var found = false;
                var pit = std.mem.splitScalar(u8, pinlist, ',');
                while (pit.next()) |tok| {
                    if (std.mem.eql(u8, tok, last_oct)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    std.debug.print("[GS] landed on {s} (octet {s}) — no open gateway, skipping\n", .{ gsips, last_oct });
                    std.process.exit(2);
                }
                std.debug.print("[GS] landed on {s} (octet {s}) — paired gateway is open, proceeding\n", .{ gsips, last_oct });
            }

            // --gs-gw: the GS backend a.b.C.d is fronted by a paired TLS gateway a.b.(C+1).d
            // (same last octet, third octet +1 — e.g. 158.115.200.46 -> 158.115.201.46). The
            // gateway routes our game by the JOINGAME token/hash to its paired backend.
            var gwbuf: [21]u8 = undefined;
            var gs_connect_host = gs_host orelse gsips;
            if (gs_host == null and gs_gw) {
                var it = std.mem.splitScalar(u8, gsips, '.');
                const o0 = it.next() orelse "";
                const o1 = it.next() orelse "";
                const o2 = it.next() orelse "";
                const o3 = it.next() orelse "";
                const c = std.fmt.parseInt(u8, o2, 10) catch 255;
                if (c < 255) {
                    gs_connect_host = std.fmt.bufPrint(&gwbuf, "{s}.{s}.{d}.{s}", .{ o0, o1, c + 1, o3 }) catch gsips;
                }
            }
            if (!std.mem.eql(u8, gs_connect_host, gsips))
                std.debug.print("[GS] GS backend {s} -> gateway {s} (token/hash from JOINGAME)\n", .{ gsips, gs_connect_host });
            const gsfd = connectResolved(gpa, gs_connect_host, gs_port) catch {
                std.debug.print("[GS] connect to {s}:{d} failed\n", .{ gs_connect_host, gs_port });
                return;
            };
            defer _ = close(gsfd);
            // TLS-mode reads block per-record; use a generous idle timeout so the timeout
            // only fires when the stream is truly quiet (never mid-record during the burst).
            setRecvTimeout(gsfd, if (gs_tls) 6000 else 2000);

            // Optionally wrap the GS socket in TLS (Blizzard's :443 D2GS farm). BNCS/MCP above
            // stayed plaintext; only this game leg is encrypted. The std TLS client drives the
            // raw fd through std.Io.File reader/writer (no engine, no extra deps).
            var threaded: std.Io.Threaded = undefined;
            var tls_rbuf: [20480]u8 = undefined; // transport ciphertext in (>= tls min_buffer_len ~16640)
            var tls_wbuf: [20480]u8 = undefined; // transport ciphertext out
            var tls_cleartext_r: [20480]u8 = undefined; // decrypted plaintext (client.reader)
            var tls_cleartext_w: [20480]u8 = undefined; // plaintext to encrypt (client.writer)
            var tls_freader: std.Io.File.Reader = undefined;
            var tls_fwriter: std.Io.File.Writer = undefined;
            var tls_client: std.crypto.tls.Client = undefined;
            var conn: GsConn = .{ .fd = gsfd };
            if (gs_tls) {
                threaded = std.Io.Threaded.init(gpa, .{});
                const tio = threaded.io();
                const gsfile = std.Io.File{ .handle = gsfd, .flags = .{ .nonblocking = false } };
                tls_freader = gsfile.readerStreaming(tio, &tls_rbuf);
                tls_fwriter = gsfile.writerStreaming(tio, &tls_wbuf);
                var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
                if (getentropy(&entropy, entropy.len) != 0) {
                    std.debug.print("[GS] getentropy failed\n", .{});
                    return;
                }
                tls_client = std.crypto.tls.Client.init(&tls_freader.interface, &tls_fwriter.interface, .{
                    .host = .{ .explicit = gs_sni }, // SNI — Blizzard's farm routes on it
                    .ca = .no_verification, // mirror the proof's rejectUnauthorized:false
                    .read_buffer = &tls_cleartext_r,
                    .write_buffer = &tls_cleartext_w,
                    .entropy = &entropy,
                    .realtime_now = .{ .nanoseconds = @as(i96, nowMs()) * 1_000_000 },
                }) catch |e| {
                    std.debug.print("[GS] TLS handshake to {s}:{d} failed: {}\n", .{ gsips, gs_port, e });
                    return;
                };
                conn.tls = &tls_client;
                std.debug.print("[GS] TLS handshake OK (SNI {s}) — D2GS-over-TLS\n", .{gs_sni});
            }
            defer if (gs_tls) threaded.deinit();

            var sbuf: [32768]u8 = undefined;
            var slen: usize = 0;
            var handshook = false;
            var sent6b = false;
            var world_bytes: usize = 0;
            var pkt_count: usize = 0;

            // World model rebuilt from the S->C stream (game/world.zig). Each framed packet is
            // fed to world.apply; the 0xAE container's inner packets are fed individually.
            var world = world_mod.World.init(gpa);
            world.verbose = verbose;
            defer world.deinit();

            // Real-client sequence: WAIT for the GS's 0xAF connection-established packet
            // (D2GS_Connected) BEFORE sending GAMELOGON. pfModes_EnterGame only sends 0x68
            // after the connecting loop sees D2GS_Connected=1 — firing 0x68 before the raw GS
            // finishes its accept handshake gets the connection dropped (what asia does).
            {
                const hs_deadline = nowMs() + 5000;
                while (!handshook and nowMs() < hs_deadline) {
                    if (slen >= 2 and sbuf[0] == 0xAF) {
                        std.debug.print("[GS] <- 0xAF connection established (D2GS_Connected)\n", .{});
                        rawDump(sbuf[0..2]);
                        std.mem.copyForwards(u8, sbuf[0 .. slen - 2], sbuf[2..slen]);
                        slen -= 2;
                        handshook = true;
                        break;
                    }
                    const nr = conn.rd(sbuf[slen..]);
                    if (nr == 0) {
                        std.debug.print("[GS] closed before connection handshake\n", .{});
                        return;
                    }
                    if (nr < 0) continue; // timeout tick
                    slen += @intCast(nr);
                }
                if (!handshook) std.debug.print("[GS] no 0xAF within 5s — sending GAMELOGON anyway\n", .{});
            }

            // GAMELOGON (0x68), 37 bytes — D2GSPacketClt0x68 (packed, raw). Offsets are the
            // engine's exact struct: nCharClass@7, nVerByte@8, consts@12/16, lang@20, name@21.
            var gl: [37]u8 = [_]u8{0} ** 37;
            gl[0] = 0x68; // nId
            std.mem.writeInt(u32, gl[1..5], ghash, .little); // nGameHash (from JOINGAME)
            std.mem.writeInt(u16, gl[5..7], gtoken, .little); // nGameToken
            gl[7] = 1; // nCharClass (Sorceress — matches the char we create)
            std.mem.writeInt(u32, gl[8..12], ver_byte, .little); // nVerByte (GetGameVersion)
            std.mem.writeInt(u32, gl[12..16], 0xed5fcc50, .little); // nVersionConstant (expansion)
            std.mem.writeInt(u32, gl[16..20], 0x91a519b6, .little); // nConstant
            gl[20] = 0; // nLanguageCode
            @memcpy(gl[21..][0..@min(charname.len, 16)], charname[0..@min(charname.len, 16)]); // szCharName[16]
            pace();
            try conn.wr(&gl);
            std.debug.print("[GS] -> GAMELOGON (0x68) token=0x{x} char=\"{s}\"\n", .{ gtoken, charname });
            // Now read the S->C stream and send JOINGAME(0x6b) only on the server's 0x02
            // LoadSuccess (NET_D2GS_CLIENT_Incoming0x02_LoadSuccess @0x45c910). Length-prefixed
            // frames (1 byte <0xF0, else 2-byte [0xF0|hi][lo]); run the GS with --no-compress.
            setRecvTimeout(gsfd, if (gs_tls) 6000 else 1500);
            const deadline = nowMs() + 8000;
            while (nowMs() < deadline) {
                var off: usize = 0;
                while (off < slen) {
                    const n = scPacketSize(sbuf[off..slen]) orelse break; // need more bytes
                    if (n == 0) { // invalid opcode = desync; resync one byte
                        std.debug.print("[GS] <- desync at 0x{x:0>2}, resyncing\n", .{sbuf[off]});
                        off += 1;
                        continue;
                    }
                    const id = sbuf[off];
                    var nb: [8]u8 = undefined;
                    std.debug.print("[GS] <- {s} 0x{x:0>2} ({d} bytes)\n", .{ packets.label(id, &nb), id, n });
                    if (verbose) rawDump(sbuf[off .. off + n]);
                    pkt_count += 1;
                    if (sent6b) world_bytes += n;
                    if (id == 0xAE and n > 3) { // compressed blob: huffman-decompress + parse inner
                        var dbuf: [16384]u8 = undefined;
                        if (huffman.decompress(sbuf[off + 3 .. off + n], &dbuf)) |dlen| {
                            std.debug.print("    decompressed {d} -> {d} bytes\n", .{ n - 3, dlen });
                            var io: usize = 0;
                            while (io < dlen) {
                                const isz = scPacketSize(dbuf[io..dlen]) orelse break;
                                if (isz == 0) break;
                                const iid = dbuf[io];
                                var inb: [8]u8 = undefined;
                                std.debug.print("    [inner] {s} 0x{x:0>2} ({d} bytes)\n", .{ packets.label(iid, &inb), iid, isz });
                                world.apply(dbuf[io .. io + isz]);
                                if (iid == 0x02 and !sent6b) {
                                    pace();
                                    try conn.wr(&[_]u8{0x6b});
                                    sent6b = true;
                                    std.debug.print("[GS] -> JOINGAME (0x6b)  (0x02 inside compressed blob)\n", .{});
                                }
                                io += isz;
                            }
                        }
                    } else {
                        world.apply(sbuf[off .. off + n]);
                    }
                    if (id == 0x02 and !sent6b) { // raw LoadSuccess -> send JOINGAME, like the real client
                        pace();
                        try conn.wr(&[_]u8{0x6b});
                        sent6b = true;
                        std.debug.print("[GS] -> JOINGAME (0x6b)  (in response to 0x02 LoadSuccess)\n", .{});
                    }
                    off += n;
                }
                if (off > 0) {
                    std.mem.copyForwards(u8, sbuf[0 .. slen - off], sbuf[off..slen]);
                    slen -= off;
                }
                const nr = conn.rd(sbuf[slen..]);
                if (nr == 0) {
                    std.debug.print("[GS] connection closed by GS ({d} packets, sent6b={})\n", .{ pkt_count, sent6b });
                    return;
                }
                if (nr < 0) continue; // timeout tick
                slen += @intCast(nr);
            }
            if (sent6b)
                std.debug.print("[GS] joined: {d} packets, {d} world bytes after 0x6b  => IN GAME\n" ++
                    "[GS] world: act={d} level={d} mapSeed=0x{x:0>8} units={d}\n", .{ pkt_count, world_bytes, world.act, world.level_id, world.map_seed, world.unitCount() })
            else
                std.debug.print("[GS] never saw 0x02 LoadSuccess ({d} packets) — 0x6b not sent\n", .{pkt_count});
            return;
        }

        // ── enter chat (BNCS), byte-for-byte like the real 1.14d client (captured via
        //    REALMD_TRACE): GETCHANNELLIST(product 4cc) -> ENTERCHAT(char + "realm,char")
        //    -> JOINCHANNEL(flags=5, "Diablo II"). The real client enters chat before
        //    accessing the ladder. ──
        var prodcode: [4]u8 = .{ 'P', 'X', '2', 'D' }; // D2XP reversed
        if (product.len == 4) prodcode = .{ product[3], product[2], product[1], product[0] };
        try send(fd, SID_GETCHANNELLIST, &prodcode);
        const ch = recvUntil(fd, SID_GETCHANNELLIST, &mb) catch &[_]u8{};
        if (ch.len > 1) std.debug.print("[SID_GETCHANNELLIST] first channel=\"{s}\"\n", .{cstrAt(ch, 0)});

        // SID_ENTERCHAT: username = char name, statstring = "<realm>,<charname>"
        var ecb: [128]u8 = undefined;
        var eo: usize = 0;
        @memcpy(ecb[eo..][0..cname_len], charname);
        eo += cname_len;
        ecb[eo] = 0;
        eo += 1;
        @memcpy(ecb[eo..][0..first_realm.len], first_realm);
        eo += first_realm.len;
        ecb[eo] = ',';
        eo += 1;
        @memcpy(ecb[eo..][0..cname_len], charname);
        eo += cname_len;
        ecb[eo] = 0;
        eo += 1;
        try send(fd, SID_ENTERCHAT, ecb[0..eo]);
        const ec = recvUntil(fd, SID_ENTERCHAT, &mb) catch &[_]u8{};
        if (ec.len > 0) std.debug.print("[SID_ENTERCHAT] unique name=\"{s}\" stat=\"{s}\"\n", .{ cstrAt(ec, 0), cstrAt(ec, cstrAt(ec, 0).len + 1) });

        // SID_JOINCHANNEL: flags=5 (D2 realm-lobby join)
        var jc: [48]u8 = undefined;
        std.mem.writeInt(u32, jc[0..4], 5, .little);
        @memcpy(jc[4 .. 4 + channel_arg.len], channel_arg);
        jc[4 + channel_arg.len] = 0;
        try send(fd, SID_JOINCHANNEL, jc[0 .. 5 + channel_arg.len]);

        // ── chat-session mode (--listen): stay connected, print every chat event, and
        //    optionally talk (--say) / kick (--kick) after --delay. Drives the 2-client demo. ──
        if (listen_sec > 0) {
            setRecvTimeout(fd, 400);
            const start = nowMs();
            const send_at = start + @as(i64, @intCast(delay_sec)) * 1000;
            const deadline = start + @as(i64, @intCast(listen_sec)) * 1000;
            var fired = (say_arg == null and kick_arg == null);
            std.debug.print("[chat] joined \"{s}\" — listening {d}s\n", .{ channel_arg, listen_sec });
            while (true) {
                const now = nowMs();
                if (!fired and now >= send_at) {
                    if (say_arg) |s| {
                        std.debug.print(">> SAY: \"{s}\"\n", .{s});
                        sendChat(fd, s);
                    }
                    if (kick_arg) |k| {
                        var kb: [128]u8 = undefined;
                        const kc = std.fmt.bufPrint(&kb, "/kick {s}", .{k}) catch k;
                        std.debug.print(">> CMD: \"{s}\"\n", .{kc});
                        sendChat(fd, kc);
                    }
                    fired = true;
                }
                if (now >= deadline) break;
                if (pumpEvents(fd) == 0) {
                    std.debug.print("[chat] *** socket closed — kicked or disconnected ***\n", .{});
                    break;
                }
            }
            return;
        }

        // Non-session: read a few chat events to show the channel state, then the ladder.
        var evi: usize = 0;
        while (evi < 10) : (evi += 1) {
            const cev = recvUntil(fd, SID_CHATEVENT, &mb) catch break;
            if (cev.len < 28) break;
            const eid = std.mem.readInt(u32, cev[0..4], .little);
            const uname = cstrAt(cev, 24);
            const text = cstrAt(cev, 24 + uname.len + 1);
            std.debug.print("[CHATEVENT] eid=0x{x} user=\"{s}\" text=\"{s}\"\n", .{ eid, uname, text });
        }

        // ── MCP_LADDERDATA (0x11) — the real client sends 3 bytes: mode 0x1b + u16(0)
        //    (captured via REALMD_TRACE). A 1-byte request makes real bnet reply 0x00. ──
        try mcpSend(mfd, MCP_LADDERDATA, &[_]u8{ 0x1b, 0, 0 });
        const ld = mcpRecv(mfd, MCP_LADDERDATA, &mb) catch &[_]u8{};
        if (ld.len < 19) {
            std.debug.print("[MCP_LADDERDATA] empty ladder (no ranked chars)\n", .{});
        } else {
            const count = std.mem.readInt(u32, ld[11..][0..4], .little);
            const esize = std.mem.readInt(u32, ld[15..][0..4], .little);
            std.debug.print("[MCP_LADDERDATA] {d} ranked entries (name width {d})\n", .{ count, esize });
            var lo: usize = 19;
            var li: usize = 0;
            while (li < count and lo + 12 + esize <= ld.len) : (li += 1) {
                lo += 8; // experience lo/hi
                const stats = std.mem.readInt(u32, ld[lo..][0..4], .little);
                lo += 4;
                const nm = cstrAt(ld, lo);
                lo += esize;
                std.debug.print("  #{d} \"{s}\" stats=0x{x}\n", .{ li + 1, nm, stats });
            }
        }
    }
}
