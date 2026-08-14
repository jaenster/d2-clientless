//! The realm leg: everything between "I have an account" and "I have a game to dial".
//!
//! BNCS gets you authenticated and tells you which realms exist. The realm hands off to MCP, which
//! owns characters and games. Only at the very end does it name a game server, a token and a hash —
//! and that triple is the whole point: it is what `d2-session` needs to enter a game.
//!
//! This is a leg, not a session. It ends the moment the ticket is minted; the chat socket stays
//! open for whoever wants it (the CLI does), but nothing here waits for the game.
//!
//! The order matters and is not negotiable: the real 1.14d client sends STARTUP -> CHARLIST2 ->
//! CHARLOGON with no MOTD in between, and real Battle.net's MCP goes silent if you insert one.

const std = @import("std");
const net = @import("d2-net-socket");
const xsha1 = @import("libd2").bnet.xsha1;
const cdkey = @import("libd2").bnet.cdkey;
const core = @import("libd2").bnet.checkrev;

pub const Socket = net.Socket;

const SID_AUTH_INFO = 0x50;
const SID_AUTH_CHECK = 0x51;
const SID_PING = 0x25;
const SID_LOGONRESPONSE2 = 0x3a;
const SID_CREATEACCOUNT2 = 0x3d;
const SID_LOGONREALMEX = 0x3e;
const SID_QUERYREALMS2 = 0x40;

const mcp = @import("libd2").bnet.mcp;

const MCP_STARTUP = @intFromEnum(mcp.Op.startup);
const MCP_CHARCREATE = @intFromEnum(mcp.Op.charcreate);
const MCP_CREATEGAME = @intFromEnum(mcp.Op.creategame);
const MCP_JOINGAME = @intFromEnum(mcp.Op.joingame);
const MCP_CHARLOGON = @intFromEnum(mcp.Op.charlogon);
const MCP_CHARLIST2 = @intFromEnum(mcp.Op.charlist2);

const CLIENT_TOKEN: u32 = 0xCAFEBABE;
/// The version-check MPQ whose algorithm `checkrev_core` implements. Any other name means a
/// different hashing routine, so our answer would be wrong — better to say so than to send it.
const EXPECTED_MPQ = "CheckRevision.mpq";

pub const Error = error{
    ShortReply,
    BadFrame,
    Closed,
    VersionRejected,
    UnexpectedCheckRevisionMPQ,
    BadKey,
    LoginFailed,
    NoRealms,
    RealmLogonFailed,
    RealmUnreachable,
    RealmRejected,
    NoSuchCharacter,
    CharLogonFailed,
    JoinFailed,
    NotInRealm,
};

pub const Options = struct {
    host: []const u8,
    port: u16 = 6112,
    /// D2DV (classic) or D2XP (expansion).
    product: []const u8 = "D2XP",
    game_version: []const u8 = "1.14.3.71",
    /// Comma-separated 26-char CD-keys. A permissive realm needs none.
    keys: ?[]const u8 = null,
    sig_ok: u8 = 1,
    /// Answer the version check even when the server names an MPQ we do not implement.
    force_checkrev: bool = false,
    /// Closed-realm password. Every 1.14d client sends the same literal.
    realm_password: []const u8 = "password",
    /// Hexdump every BNCS and MCP packet.
    verbose: bool = false,
    /// Narrate each step. The CLI wants this; a daemon generally does not.
    log: bool = true,
};

/// A character as the realm describes it, which is all we know before entering a game.
pub const Character = struct {
    name_buf: [24]u8 = [_]u8{0} ** 24,
    name_len: usize = 0,
    /// nCharClass, as CharStats.txt orders them. GAMELOGON carries it, and getting it wrong
    /// gives the GS a character whose skills and animations do not match its save.
    class: u8 = 0,
    level: u8 = 1,
    expansion: bool = true,

    pub fn name(self: *const Character) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// What JOINGAME hands back: where the game lives and how to prove we were let in.
pub const Ticket = struct {
    gs_ip: [4]u8,
    gs_host_buf: [64]u8 = [_]u8{0} ** 64,
    gs_host_len: usize = 0,
    /// nGameToken — resolves the game on the GS.
    token: u16,
    /// nGameHash — proves the realm sent us.
    hash: u32,
    character: Character,

    pub fn gsHost(self: *const Ticket) []const u8 {
        return self.gs_host_buf[0..self.gs_host_len];
    }
};

pub const CreateResult = mcp.CreateResult;

pub const JoinResult = mcp.JoinResult;

pub const Difficulty = mcp.Difficulty;

pub const GameOptions = mcp.GameOptions;

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

/// The statstring the char-select screen renders each character from. Only three fields matter
/// to us; the rest is body-component graphics. Byte 13 carries class+1 because every byte is
/// sent inside a C string and a zero would truncate the record.
fn readStatString(stat: []const u8, into: *Character) void {
    if (stat.len > 13) into.class = if (stat[13] > 0) stat[13] - 1 else 0;
    if (stat.len > 25) into.level = stat[25];
    if (stat.len > 26) into.expansion = (stat[26] & 0x04) != 0;
}

pub const Realm = struct {
    gpa: std.mem.Allocator,
    opts: Options,
    bncs: Socket,
    mcp: ?Socket = null,
    server_token: u32 = 0,
    /// The MCP handoff the realm logon replied with, forwarded verbatim into MCP_STARTUP.
    handoff: [128]u8 = [_]u8{0} ** 128,
    handoff_len: usize = 0,
    character: Character = .{},
    /// Which host we dialled, so a NATed MCP address can fall back to it.
    gateway: []const u8 = "",

    rx: [16384]u8 = undefined,
    rx_len: usize = 0,
    mrx: [16384]u8 = undefined,
    mrx_len: usize = 0,

    fn say(self: *const Realm, comptime fmt: []const u8, args: anytype) void {
        if (self.opts.log) std.debug.print(fmt, args);
    }

    fn dump(self: *const Realm, proto: []const u8, id: u8, body: []const u8) void {
        if (!self.opts.verbose) return;
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

    // ── BNCS framing: [0xFF][id][u16 len incl header][body] ──

    pub fn send(self: *Realm, id: u8, body: []const u8) !void {
        var hdr: [4]u8 = .{ 0xFF, id, 0, 0 };
        std.mem.writeInt(u16, hdr[2..4], @intCast(body.len + 4), .little);
        try net.writeAll(self.bncs, &hdr);
        try net.writeAll(self.bncs, body);
    }

    /// Read frames until one with `want` arrives, echoing SID_PING along the way — the server
    /// pings mid-handshake and a client that ignores it gets dropped.
    pub fn recvUntil(self: *Realm, want: u8, out: []u8) ![]const u8 {
        while (true) {
            while (self.rx_len >= 4 and self.rx[0] == 0xFF) {
                const id = self.rx[1];
                const plen = std.mem.readInt(u16, self.rx[2..4], .little);
                if (plen < 4 or plen > self.rx.len) return Error.BadFrame;
                if (self.rx_len < plen) break;
                const body = self.rx[4..plen];
                self.dump("BNCS", id, body);
                if (id == 0x4a or id == 0x4c)
                    self.say("[WORK 0x{x:0>2}] \"{s}\"\n", .{ id, cstrAt(body, 0) });
                if (id == SID_PING) {
                    var echo: [8]u8 = .{ 0xFF, SID_PING, 8, 0, 0, 0, 0, 0 };
                    @memcpy(echo[4..8], body[0..4]);
                    try net.writeAll(self.bncs, &echo);
                } else if (id == want) {
                    const blen = plen - 4;
                    @memcpy(out[0..blen], body);
                    std.mem.copyForwards(u8, self.rx[0 .. self.rx_len - plen], self.rx[plen..self.rx_len]);
                    self.rx_len -= plen;
                    return out[0..blen];
                }
                std.mem.copyForwards(u8, self.rx[0 .. self.rx_len - plen], self.rx[plen..self.rx_len]);
                self.rx_len -= plen;
            }
            const got = net.read(self.bncs, self.rx[self.rx_len..].ptr, self.rx.len - self.rx_len);
            if (got <= 0) return Error.Closed;
            self.rx_len += @intCast(got);
        }
    }

    // ── MCP framing: [u16 len incl header][id][body], on its own connection ──

    fn mcpSend(self: *Realm, id: u8, body: []const u8) !void {
        const fd = self.mcp orelse return Error.NotInRealm;
        var hdr: [3]u8 = undefined;
        std.mem.writeInt(u16, hdr[0..2], @intCast(body.len + 3), .little);
        hdr[2] = id;
        try net.writeAll(fd, &hdr);
        if (body.len > 0) try net.writeAll(fd, body);
    }

    fn mcpRecv(self: *Realm, want: u8, out: []u8) ![]const u8 {
        const fd = self.mcp orelse return Error.NotInRealm;
        while (true) {
            while (self.mrx_len >= 3) {
                const plen = std.mem.readInt(u16, self.mrx[0..2], .little);
                if (plen < 3 or plen > self.mrx.len) return Error.BadFrame;
                if (self.mrx_len < plen) break;
                const id = self.mrx[2];
                const blen = plen - 3;
                self.dump("MCP", id, self.mrx[3..plen]);
                if (id == want) {
                    @memcpy(out[0..blen], self.mrx[3..plen]);
                    std.mem.copyForwards(u8, self.mrx[0 .. self.mrx_len - plen], self.mrx[plen..self.mrx_len]);
                    self.mrx_len -= plen;
                    return out[0..blen];
                }
                std.mem.copyForwards(u8, self.mrx[0 .. self.mrx_len - plen], self.mrx[plen..self.mrx_len]);
                self.mrx_len -= plen;
            }
            const got = net.read(fd, self.mrx[self.mrx_len..].ptr, self.mrx.len - self.mrx_len);
            if (got <= 0) return Error.Closed;
            self.mrx_len += @intCast(got);
        }
    }

    /// Connect and clear the version gauntlet: AUTH_INFO names the challenge, AUTH_CHECK answers
    /// it. No account is involved yet — this much works against any server, which is exactly why
    /// it is a separate step.
    pub fn connect(gpa: std.mem.Allocator, opts: Options) !Realm {
        const fd = try net.connectResolved(gpa, opts.host, opts.port);
        errdefer _ = net.close(fd);
        var self = Realm{ .gpa = gpa, .opts = opts, .bncs = fd, .gateway = opts.host };
        try net.writeAll(fd, &[_]u8{0x01}); // protocol selector: BNCS

        var body: [128]u8 = undefined;
        var w: usize = 0;
        for ([_]u32{ 0, fourcc("IX86"), fourcc(opts.product), 0x0E, 0, 0, 0, 0, 0 }) |v| {
            std.mem.writeInt(u32, body[w..][0..4], v, .little);
            w += 4;
        }
        for ("USA\x00United States\x00") |c| {
            body[w] = c;
            w += 1;
        }
        try self.send(SID_AUTH_INFO, body[0..w]);

        var aibuf: [4096]u8 = undefined;
        const ai = try self.recvUntil(SID_AUTH_INFO, &aibuf);
        if (ai.len < 20) return Error.ShortReply;
        self.server_token = std.mem.readInt(u32, ai[4..8], .little);
        const mpq = cstrAt(ai, 20);
        const challenge = cstrAt(ai, 20 + mpq.len + 1);
        self.say("\n[AUTH_INFO] serverToken=0x{x:0>8}  mpq=\"{s}\"  challenge=\"{s}\"\n", .{ self.server_token, mpq, challenge });

        // Modern bnet sends a base64 challenge; classic realmd/pvpgn sends the legacy
        // "A=1 B=1 C=1 …" formula computed over game files a clientless tool does not ship.
        // Permissive realms accept any AUTH_CHECK, so the classic path sends placeholders.
        var full_buf: [64]u8 = undefined;
        var exe_version: u32 = 0;
        var exe_hash: u32 = undefined;
        var exe_info: []const u8 = undefined;
        if (std.mem.indexOfScalar(u8, challenge, ' ') != null or std.mem.startsWith(u8, challenge, "A=")) {
            exe_version = 0x01000001;
            exe_hash = 0xdeadbeef;
            exe_info = "";
            self.say("[checkrev] CLASSIC challenge -> placeholder exeHash=0x{x:0>8} (permissive realm)\n", .{exe_hash});
        } else {
            if (!std.mem.eql(u8, mpq, EXPECTED_MPQ)) {
                self.say("[checkrev] UNEXPECTED MPQ \"{s}\" — we only implement \"{s}\". " ++
                    "Not sending a (likely wrong) response.\n", .{ mpq, EXPECTED_MPQ });
                if (!opts.force_checkrev) return Error.UnexpectedCheckRevisionMPQ;
            }
            const full = core.response(challenge, opts.game_version, opts.sig_ok, &full_buf) orelse return Error.ShortReply;
            exe_hash = std.mem.readInt(u32, full[0..4], .little);
            exe_info = full[4..];
            self.say("[checkrev] response=\"{s}\"  -> exeHash=0x{x:0>8}  exeInfo=\"{s}\"\n", .{ full, exe_hash, exe_info });
        }

        var cb: [512]u8 = undefined;
        var nkeys: u32 = 0;
        const hdr_keys_off = 12; // numKeys, backfilled once the keys are counted
        std.mem.writeInt(u32, cb[0..4], CLIENT_TOKEN, .little);
        std.mem.writeInt(u32, cb[4..8], exe_version, .little);
        std.mem.writeInt(u32, cb[8..12], exe_hash, .little);
        std.mem.writeInt(u32, cb[16..20], 0, .little); // spawn
        var cw: usize = 20;
        var keyit = std.mem.tokenizeScalar(u8, opts.keys orelse "", ',');
        while (keyit.next()) |k| {
            const blk = cdkey.keyBlock26(k, CLIENT_TOKEN, self.server_token) orelse {
                self.say("[keys] bad 26-char key: {s}\n", .{k});
                return Error.BadKey;
            };
            var wire: [36]u8 = undefined;
            blk.writeWire(&wire);
            @memcpy(cb[cw .. cw + 36], &wire);
            cw += 36;
            nkeys += 1;
            self.say("[keys] key[{d}] product=0x{x:0>8} public=0x{x:0>8}\n", .{ nkeys - 1, blk.product, blk.public });
        }
        std.mem.writeInt(u32, cb[hdr_keys_off..][0..4], nkeys, .little);
        @memcpy(cb[cw .. cw + exe_info.len], exe_info);
        cw += exe_info.len;
        cb[cw] = 0;
        cw += 1;
        for ("probe\x00") |c| { // CD-key owner
            cb[cw] = c;
            cw += 1;
        }
        try self.send(SID_AUTH_CHECK, cb[0..cw]);

        var acbuf: [1024]u8 = undefined;
        const ac = self.recvUntil(SID_AUTH_CHECK, &acbuf) catch |e| {
            self.say("\n[AUTH_CHECK] no reply ({s}) — server dropped the packet (malformed/keyless).\n", .{@errorName(e)});
            return e;
        };
        if (ac.len < 4) return Error.ShortReply;
        const result = std.mem.readInt(u32, ac[0..4], .little);
        self.say("\n[AUTH_CHECK] result=0x{x:0>4}  info=\"{s}\"  => {s}\n", .{ result, cstrAt(ac, 4), authMeaning(result) });
        return self;
    }

    pub fn deinit(self: *Realm) void {
        if (self.mcp) |fd| _ = net.close(fd);
        self.mcp = null;
        _ = net.close(self.bncs);
    }

    /// Register an account. CREATE hashes the password once; LOGON hashes it twice with both
    /// tokens — using the wrong one of the two is a silent "incorrect password".
    pub fn createAccount(self: *Realm, account: []const u8, password: []const u8) !bool {
        const pwhash = xsha1.passwordHash(password);
        var nb: [320]u8 = undefined;
        @memcpy(nb[0..20], &pwhash);
        @memcpy(nb[20 .. 20 + account.len], account);
        nb[20 + account.len] = 0;
        try self.send(SID_CREATEACCOUNT2, nb[0 .. 20 + account.len + 1]);
        var nrbuf: [256]u8 = undefined;
        const nr = try self.recvUntil(SID_CREATEACCOUNT2, &nrbuf);
        const st = if (nr.len >= 4) std.mem.readInt(u32, nr[0..4], .little) else 0xffffffff;
        self.say("[CREATEACCOUNT2] account=\"{s}\" status={d}  => {s}\n", .{ account, st, if (st == 0) "created" else "failed/exists" });
        return st == 0;
    }

    pub fn login(self: *Realm, account: []const u8, password: []const u8) !void {
        const inner = xsha1.passwordHash(password);
        const pwhash = xsha1.doubleHash(CLIENT_TOKEN, self.server_token, inner);
        var pb: [320]u8 = undefined;
        std.mem.writeInt(u32, pb[0..4], CLIENT_TOKEN, .little);
        std.mem.writeInt(u32, pb[4..8], self.server_token, .little);
        @memcpy(pb[8..28], &pwhash);
        @memcpy(pb[28 .. 28 + account.len], account);
        pb[28 + account.len] = 0;
        try self.send(SID_LOGONRESPONSE2, pb[0 .. 28 + account.len + 1]);
        var lbuf: [256]u8 = undefined;
        const lr = try self.recvUntil(SID_LOGONRESPONSE2, &lbuf);
        const res = if (lr.len >= 4) std.mem.readInt(u32, lr[0..4], .little) else 0xffffffff;
        self.say("[LOGONRESPONSE2] account=\"{s}\" result={d}  => {s}\n", .{ account, res, switch (res) {
            0 => "OK — account+password accepted",
            1 => "no such account",
            2 => "incorrect password",
            else => "other",
        } });
        if (res != 0) return Error.LoginFailed;
    }

    /// Log on to a realm and open MCP behind it. `name` picks a realm by title; null takes the
    /// first listed, which is the only one on our own server.
    pub fn enterRealm(self: *Realm, name: ?[]const u8) !void {
        // The body must be EMPTY. Real bnet closes the connection on a non-empty QUERYREALMS2.
        try self.send(SID_QUERYREALMS2, &[_]u8{});
        var qbuf: [4096]u8 = undefined;
        const qr = try self.recvUntil(SID_QUERYREALMS2, &qbuf);
        var chosen: []const u8 = "";
        if (qr.len >= 8) {
            const count = std.mem.readInt(u32, qr[4..8], .little);
            self.say("[QUERYREALMS2] {d} realm(s):\n", .{count});
            var off: usize = 8;
            var n: u32 = 0;
            while (n < count and off + 4 <= qr.len) : (n += 1) {
                off += 4; // per-realm unknown dword
                const title = cstrAt(qr, off);
                off += title.len + 1;
                const desc = cstrAt(qr, off);
                off += desc.len + 1;
                const wanted = if (name) |want| std.ascii.eqlIgnoreCase(want, title) else chosen.len == 0;
                if (wanted) chosen = title;
                self.say("  - \"{s}\"  ({s})\n", .{ title, desc });
            }
        }
        if (chosen.len == 0) return Error.NoRealms;

        const realm_pw = xsha1.doubleHash(CLIENT_TOKEN, self.server_token, xsha1.xsha1(self.opts.realm_password));
        var rb: [128]u8 = undefined;
        std.mem.writeInt(u32, rb[0..4], CLIENT_TOKEN, .little);
        @memcpy(rb[4..24], &realm_pw);
        @memcpy(rb[24 .. 24 + chosen.len], chosen);
        rb[24 + chosen.len] = 0;
        try self.send(SID_LOGONREALMEX, rb[0 .. 24 + chosen.len + 1]);
        var rrbuf: [256]u8 = undefined;
        const rr = try self.recvUntil(SID_LOGONREALMEX, &rrbuf);
        // Real bnet's success layout differs from realmd's, so success is read from the reply
        // LENGTH, not a status dword: ~8 bytes is cookie+status (a failure), while a long reply
        // carries the MCP handoff — cookie, status, chunk1, ip, port, chunk2, unique name.
        if (rr.len < 30) {
            const status = if (rr.len >= 8) std.mem.readInt(u32, rr[4..8], .little) else 0xffffffff;
            self.say("[LOGONREALMEX] realm=\"{s}\" => FAILED (status=0x{x})\n", .{ chosen, status });
            return Error.RealmLogonFailed;
        }
        self.say("[LOGONREALMEX] realm=\"{s}\" => OK ({d}-byte MCP handoff)\n", .{ chosen, rr.len });
        self.handoff_len = @min(rr.len, self.handoff.len);
        @memcpy(self.handoff[0..self.handoff_len], rr[0..self.handoff_len]);

        const ip4 = rr[16..20];
        const mport = std.mem.readInt(u16, rr[20..22], .big);
        var ipstr: [20]u8 = undefined;
        const ipfmt = std.fmt.bufPrint(&ipstr, "{d}.{d}.{d}.{d}", .{ ip4[0], ip4[1], ip4[2], ip4[3] }) catch return Error.ShortReply;
        // Real bnet answers with d2cs's PRIVATE (NATed) address, unreachable from outside. Falling
        // back to the host we dialled covers the case where the gateway proxies MCP as well.
        const priv = ip4[0] == 10 or (ip4[0] == 192 and ip4[1] == 168) or
            (ip4[0] == 172 and ip4[1] >= 16 and ip4[1] <= 31) or ip4[0] == 127 or ip4[0] == 0;
        const ips = if (priv) self.gateway else ipfmt;
        if (priv)
            self.say("[MCP] realm returned PRIVATE ip {s}:{d} (NAT) -> retrying via gateway {s}:{d}\n", .{ ipfmt, mport, ips, mport })
        else
            self.say("[MCP] connecting to {s}:{d}\n", .{ ips, mport });

        const mfd = net.connectResolved(self.gpa, ips, mport) catch {
            self.say("[MCP] connect failed\n", .{});
            return Error.RealmUnreachable;
        };
        self.mcp = mfd;
        self.mrx_len = 0;
        try net.writeAll(mfd, &[_]u8{0x01}); // MCP protocol selector

        // STARTUP forwards cookie+status+chunk1(8)+chunk2(48) straight out of the realm reply.
        var sb: [64]u8 = [_]u8{0} ** 64;
        @memcpy(sb[0..16], rr[0..16]);
        if (rr.len >= 72) @memcpy(sb[16..64], rr[24..72]);
        try self.mcpSend(MCP_STARTUP, &sb);
        var mb: [8192]u8 = undefined;
        const sr = self.mcpRecv(MCP_STARTUP, &mb) catch {
            self.say("[MCP_STARTUP] no reply from {s}:{d} — d2cs unreachable (realm logon succeeded " ++
                "but the char/game server is NATed)\n", .{ ips, mport });
            return Error.RealmUnreachable;
        };
        const sres = if (sr.len >= 4) std.mem.readInt(u32, sr[0..4], .little) else 0xffffffff;
        self.say("[MCP_STARTUP] result=0x{x}  => {s}\n", .{ sres, if (sres == 0) "session accepted (in the realm)" else "rejected" });
        if (sres != 0) return Error.RealmRejected;
    }

    /// List the account's characters. Also where class and level come from — the realm never
    /// states them outright, they are encoded in the char-select statstring.
    pub fn characters(self: *Realm, out: []Character) ![]Character {
        var req: [4]u8 = undefined;
        std.mem.writeInt(u32, &req, 8, .little);
        try self.mcpSend(MCP_CHARLIST2, &req);
        var mb: [8192]u8 = undefined;
        const cl = self.mcpRecv(MCP_CHARLIST2, &mb) catch return out[0..0];
        if (cl.len < 8) return out[0..0];
        const total = std.mem.readInt(u32, cl[2..6], .little);
        const returned = std.mem.readInt(u16, cl[6..8], .little);
        self.say("[MCP_CHARLIST2] total={d} returned={d}\n", .{ total, returned });
        var off: usize = 8;
        var n: usize = 0;
        while (n < returned and n < out.len and off + 4 < cl.len) : (n += 1) {
            off += 4; // expiry
            const name = cstrAt(cl, off);
            off += name.len + 1;
            const stat = cstrAt(cl, off);
            off += stat.len + 1;
            out[n] = .{};
            const keep = @min(name.len, out[n].name_buf.len);
            @memcpy(out[n].name_buf[0..keep], name[0..keep]);
            out[n].name_len = keep;
            readStatString(stat, &out[n]);
            self.say("  - char \"{s}\" class={d} level={d}\n", .{ out[n].name(), out[n].class, out[n].level });
        }
        return out[0..n];
    }

    /// Create a character. Only reached when the account has none, or the caller asks for it.
    pub fn createCharacter(self: *Realm, name: []const u8, class: u8, expansion: bool) !Character {
        var ccb: [64]u8 = undefined;
        std.mem.writeInt(u32, ccb[0..4], class, .little);
        std.mem.writeInt(u16, ccb[4..6], if (expansion) 0x20 else 0x00, .little); // status: 0x20 = LoD, softcore
        @memcpy(ccb[6 .. 6 + name.len], name);
        ccb[6 + name.len] = 0;
        try self.mcpSend(MCP_CHARCREATE, ccb[0 .. 7 + name.len]);
        var mb: [1024]u8 = undefined;
        const ccr = self.mcpRecv(MCP_CHARCREATE, &mb) catch &[_]u8{};
        const res = if (ccr.len >= 4) std.mem.readInt(u32, ccr[0..4], .little) else 0xffffffff;
        self.say("[MCP_CHARCREATE] \"{s}\" class={d} result=0x{x}  => {s}\n", .{ name, class, res, if (res == 0) "created" else "failed" });
        if (res != 0) return Error.NoSuchCharacter;
        var made = Character{ .class = class, .expansion = expansion };
        const keep = @min(name.len, made.name_buf.len);
        @memcpy(made.name_buf[0..keep], name[0..keep]);
        made.name_len = keep;
        return made;
    }

    /// Pick a character and log on to it. `wanted` names one; null takes the first listed. This
    /// is what makes the realm connection stateful — games are created BY a character.
    pub fn chooseCharacter(self: *Realm, wanted: ?[]const u8) !Character {
        var list: [24]Character = undefined;
        const found = try self.characters(&list);
        var picked: ?Character = null;
        for (found) |c| {
            if (c.name_len == 0) continue;
            const match = if (wanted) |want| std.ascii.eqlIgnoreCase(want, c.name()) else true;
            if (match) {
                picked = c;
                break;
            }
        }
        if (picked == null) {
            if (wanted) |want| {
                self.say("[MCP_CHARLIST2] no character named \"{s}\" on this account\n", .{want});
                return Error.NoSuchCharacter;
            }
            return Error.NoSuchCharacter;
        }
        const chosen = picked.?;

        var clb: [40]u8 = undefined;
        @memcpy(clb[0..chosen.name_len], chosen.name());
        clb[chosen.name_len] = 0;
        try self.mcpSend(MCP_CHARLOGON, clb[0 .. chosen.name_len + 1]);
        var mb: [1024]u8 = undefined;
        const clr = self.mcpRecv(MCP_CHARLOGON, &mb) catch &[_]u8{};
        const res = if (clr.len >= 4) std.mem.readInt(u32, clr[0..4], .little) else 0xffffffff;
        self.say("[MCP_CHARLOGON] \"{s}\" result=0x{x}  => {s}\n", .{ chosen.name(), res, if (res == 0) "logged onto char" else "failed" });
        if (res != 0) return Error.CharLogonFailed;
        self.character = chosen;
        return chosen;
    }

    pub fn createGame(self: *Realm, game: GameOptions) !CreateResult {
        var b: [256]u8 = undefined;
        std.mem.writeInt(u16, b[0..2], 1, .little); // request id
        std.mem.writeInt(u32, b[2..6], @intFromEnum(game.difficulty), .little);
        b[6] = 1; // unknown, always 1
        b[7] = 0; // player difficulty
        b[8] = game.max_players;
        var w: usize = 9;
        @memcpy(b[w..][0..game.name.len], game.name);
        w += game.name.len;
        b[w] = 0;
        w += 1;
        @memcpy(b[w..][0..game.password.len], game.password);
        w += game.password.len;
        b[w] = 0;
        w += 1;
        @memcpy(b[w..][0..game.description.len], game.description);
        w += game.description.len;
        b[w] = 0;
        w += 1;
        try self.mcpSend(MCP_CREATEGAME, b[0..w]);
        var mb: [1024]u8 = undefined;
        const r = self.mcpRecv(MCP_CREATEGAME, &mb) catch &[_]u8{};
        const result: CreateResult = @enumFromInt(if (r.len >= 10) std.mem.readInt(u32, r[6..10], .little) else 0xffffffff);
        const token = if (r.len >= 4) std.mem.readInt(u16, r[2..4], .little) else 0;
        self.say("[MCP_CREATEGAME] \"{s}\" token=0x{x} result=0x{x}  => {s}\n", .{ game.name, token, @intFromEnum(result), result.describe() });
        return result;
    }

    /// Join a game and mint the ticket. The reply names the game server, so this is the only
    /// place that knows where the game physically is.
    pub fn joinGame(self: *Realm, name: []const u8, password: []const u8) !Ticket {
        var b: [128]u8 = undefined;
        std.mem.writeInt(u16, b[0..2], 2, .little); // request id
        var w: usize = 2;
        @memcpy(b[w..][0..name.len], name);
        w += name.len;
        b[w] = 0;
        w += 1;
        @memcpy(b[w..][0..password.len], password);
        w += password.len;
        b[w] = 0;
        w += 1;
        try self.mcpSend(MCP_JOINGAME, b[0..w]);
        var mb: [1024]u8 = undefined;
        const r = self.mcpRecv(MCP_JOINGAME, &mb) catch &[_]u8{};
        if (r.len < 18) {
            self.say("[MCP_JOINGAME] short reply ({d} B)\n", .{r.len});
            return Error.ShortReply;
        }
        var ticket = Ticket{
            .gs_ip = .{ r[6], r[7], r[8], r[9] },
            .token = std.mem.readInt(u16, r[2..4], .little),
            .hash = std.mem.readInt(u32, r[10..14], .little),
            .character = self.character,
        };
        // 0.0.0.0 is not an address, it is "wherever you are talking to me from" — a realm that
        // was never told its own public address answers with it. Dialling it fails outright, so
        // fall back to the host we reached the realm on, which is where the GS is too.
        const unspecified = std.mem.allEqual(u8, &ticket.gs_ip, 0);
        const host = if (unspecified)
            std.fmt.bufPrint(&ticket.gs_host_buf, "{s}", .{self.gateway}) catch return Error.ShortReply
        else
            std.fmt.bufPrint(&ticket.gs_host_buf, "{d}.{d}.{d}.{d}", .{ r[6], r[7], r[8], r[9] }) catch return Error.ShortReply;
        ticket.gs_host_len = host.len;
        if (unspecified) self.say("[MCP_JOINGAME] realm named 0.0.0.0 -> using {s}\n", .{self.gateway});
        const result: JoinResult = @enumFromInt(std.mem.readInt(u32, r[14..18], .little));
        self.say("[MCP_JOINGAME] token=0x{x} gs={s} hash=0x{x} result=0x{x}  => {s}\n", .{
            ticket.token, ticket.gsHost(), ticket.hash, @intFromEnum(result), result.describe(),
        });
        if (result != .ok) return Error.JoinFailed;
        return ticket;
    }
};

pub const Login = struct {
    account: []const u8,
    password: []const u8,
    /// Which character to play. Null takes the first the realm lists.
    character: ?[]const u8 = null,
};

/// The whole leg in one call: log on, pick a character, and land in a game — creating it if it is
/// not there yet. This is what a bot wants; the CLI drives the steps itself because it has
/// something to say between each of them.
///
/// The caller owns the connection because it outlives the ticket: closing MCP while in a game
/// ends the character's realm session, which is not something this function can decide.
pub fn enterGame(self: *Realm, who: Login, game: GameOptions) !Ticket {
    try self.login(who.account, who.password);
    try self.enterRealm(null);
    _ = try self.chooseCharacter(who.character);
    // A failed create is not the end: the game may already be up, made by another player or left
    // over from an earlier run. Fall through to JOINGAME either way — if it truly does not exist
    // the join says so, with a reason, which is better than guessing from the create code.
    const made = try self.createGame(game);
    if (made != .created) self.say("[MCP_CREATEGAME] create failed -> trying to JOIN the existing game\n", .{});
    return self.joinGame(game.name, game.password);
}

test "a statstring gives up class, level and expansion" {
    var c = Character{};
    // Byte 13 is class+1 (a zero would truncate the C string), 25 is level, 26 bit 2 is expansion.
    var stat = [_]u8{0xff} ** 36;
    stat[13] = 2; // class 1 = Sorceress
    stat[25] = 92;
    stat[26] = 0x04;
    readStatString(&stat, &c);
    try std.testing.expectEqual(@as(u8, 1), c.class);
    try std.testing.expectEqual(@as(u8, 92), c.level);
    try std.testing.expect(c.expansion);

    stat[26] = 0x08; // classic: the expansion bit is clear
    readStatString(&stat, &c);
    try std.testing.expect(!c.expansion);
}

test "a short statstring leaves the defaults alone rather than reading past it" {
    var c = Character{ .class = 3, .level = 7 };
    readStatString(&[_]u8{ 1, 2, 3 }, &c);
    try std.testing.expectEqual(@as(u8, 3), c.class);
    try std.testing.expectEqual(@as(u8, 7), c.level);
}
