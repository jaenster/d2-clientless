//! bnftp-probe — a clientless BNFTP discovery client.
//!
//! BNFTP (Battle.net File Transfer, protocol selector 0x02) is UNAUTHENTICATED:
//! no CD-key, no SRP, no login. To discover what a real server serves we do two
//! CD-key-free steps:
//!
//!   1. Connect 0x01 → SID_AUTH_INFO. The reply is unconditional and names the
//!      version-check MPQ (filename + filetime) the server wants. Hexdump it.
//!   2. Open a fresh 0x02 connection → BNFTP-request that filename. Hexdump the
//!      raw reply and save the file bytes so we can diff the header layout (and
//!      the MPQ contents) against our own src/realm/server/bnftp.zig.
//!
//! Egress can go through a SOCKS5 proxy (`--socks5 host:port`) so the probe
//! reaches the target from a chosen IP — e.g. an `ssh -D 1080 hetzner` dynamic
//! forward, or a standalone proxy on a Hetzner box. With SOCKS5 the proxy does
//! the DNS, so the target host is sent as a domain name.
//!
//!   zig build bnftp-probe -- [opts] <target-host> [product] [filename]
//!   opts: --socks5 H:P  --socks5-auth U:P  --port N (default 6112)
//!         --proto-ver 0xNNNN (BNFTP version, default 0x0100)
//!   product: 4CC, default D2XP (LoD). Use D2DV for classic.
const std = @import("std");

// ── libc sockets (native host target; std.posix socket wrappers are gone in 0.16) ──
const Socket = c_int;
extern "c" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) c_int;
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: c_uint) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn setsockopt(fd: c_int, level: c_int, optname: c_int, optval: *const anyopaque, optlen: c_uint) c_int;
// open is variadic in C — MUST declare `...` or the mode arg lands wrong on arm64.
extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;

const SOCK_STREAM: c_int = 1;

/// Create/truncate `path` and write `data`. Uses libc directly (std.fs is
/// reworked under the 0.16 Io interface and std.posix.open is gone).
fn writeFile(path: [*:0]const u8, data: []const u8) !void {
    const flags: c_int = @bitCast(std.posix.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true });
    const fd = open(path, flags, @as(c_uint, 0o644));
    if (fd < 0) return error.OpenFailed;
    defer _ = close(fd);
    try writeAll(fd, data);
}

var recv_timeout_ms: u32 = 20000; // SO_RCVTIMEO default; --timeout overrides

fn setRecvTimeout(fd: Socket, ms: u32) void {
    const tv = std.posix.timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    _ = setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, &tv, @sizeOf(std.posix.timeval));
}

fn writeAll(fd: Socket, buf: []const u8) !void {
    var sent: usize = 0;
    while (sent < buf.len) {
        const n = write(fd, buf.ptr + sent, buf.len - sent);
        if (n <= 0) return error.WriteFailed;
        sent += @intCast(n);
    }
}

fn readFull(fd: Socket, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        const n = read(fd, buf.ptr + got, buf.len - got);
        if (n <= 0) return error.SocketClosed;
        got += @intCast(n);
    }
}

/// Read up to buf.len, stopping at EOF/timeout. Returns the bytes read.
fn readSome(fd: Socket, buf: []u8) usize {
    const n = read(fd, buf.ptr, buf.len);
    return if (n <= 0) 0 else @intCast(n);
}

/// TCP-connect to host:port, resolving via libc getaddrinfo.
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
            setRecvTimeout(fd, recv_timeout_ms);
            return fd;
        }
        _ = close(fd);
    }
    return error.ConnectFailed;
}

// ── SOCKS5 client (RFC 1928 / 1929) ───────────────────────────────────────────
const Proxy = struct { host: []const u8, port: u16, user: []const u8 = "", pass: []const u8 = "" };

fn socks5Connect(fd: Socket, px: Proxy, target: []const u8, tport: u16) !void {
    // Greeting: offer no-auth and (if creds given) user/pass.
    var greet: [4]u8 = undefined;
    greet[0] = 0x05;
    if (px.user.len > 0) {
        greet[1] = 2;
        greet[2] = 0x00;
        greet[3] = 0x02;
        try writeAll(fd, greet[0..4]);
    } else {
        greet[1] = 1;
        greet[2] = 0x00;
        try writeAll(fd, greet[0..3]);
    }
    var sel: [2]u8 = undefined;
    try readFull(fd, &sel);
    if (sel[0] != 0x05) return error.Socks5BadVersion;
    switch (sel[1]) {
        0x00 => {}, // no auth
        0x02 => {
            if (px.user.len == 0) return error.Socks5AuthRequired;
            var ab: [600]u8 = undefined;
            var n: usize = 0;
            ab[n] = 0x01;
            n += 1;
            ab[n] = @intCast(px.user.len);
            n += 1;
            @memcpy(ab[n..][0..px.user.len], px.user);
            n += px.user.len;
            ab[n] = @intCast(px.pass.len);
            n += 1;
            @memcpy(ab[n..][0..px.pass.len], px.pass);
            n += px.pass.len;
            try writeAll(fd, ab[0..n]);
            var ar: [2]u8 = undefined;
            try readFull(fd, &ar);
            if (ar[1] != 0x00) return error.Socks5AuthFailed;
        },
        else => return error.Socks5NoAcceptableAuth,
    }
    // CONNECT request, ATYP=domain so the proxy resolves DNS.
    var req: [600]u8 = undefined;
    var n: usize = 0;
    req[n] = 0x05;
    n += 1; // ver
    req[n] = 0x01;
    n += 1; // CONNECT
    req[n] = 0x00;
    n += 1; // rsv
    req[n] = 0x03;
    n += 1; // ATYP domain
    req[n] = @intCast(target.len);
    n += 1;
    @memcpy(req[n..][0..target.len], target);
    n += target.len;
    std.mem.writeInt(u16, req[n..][0..2], tport, .big);
    n += 2;
    try writeAll(fd, req[0..n]);
    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    var head: [4]u8 = undefined;
    try readFull(fd, &head);
    if (head[0] != 0x05) return error.Socks5BadVersion;
    if (head[1] != 0x00) {
        std.debug.print("socks5 CONNECT failed, REP=0x{x:0>2}\n", .{head[1]});
        return error.Socks5ConnectRejected;
    }
    const bnd_len: usize = switch (head[3]) {
        0x01 => 4, // IPv4
        0x04 => 16, // IPv6
        0x03 => blk: { // domain: 1 len byte + that many
            var l: [1]u8 = undefined;
            try readFull(fd, &l);
            break :blk l[0];
        },
        else => return error.Socks5BadAtyp,
    };
    var skip: [16 + 2]u8 = undefined;
    try readFull(fd, skip[0 .. bnd_len + 2]); // bnd addr + port, discarded
}

/// Dial target:port either directly or through the SOCKS5 proxy.
fn dial(gpa: std.mem.Allocator, target: []const u8, tport: u16, proxy: ?Proxy) !Socket {
    if (proxy) |px| {
        const fd = try connectResolved(gpa, px.host, px.port);
        errdefer _ = close(fd);
        try socks5Connect(fd, px, target, tport);
        return fd;
    }
    return connectResolved(gpa, target, tport);
}

// ── BNCS framing: <0xFF, id, u16 len> + body ──────────────────────────────────
fn bncsSend(fd: Socket, id: u8, body: []const u8) !void {
    var hdr: [4]u8 = .{ 0xFF, id, 0, 0 };
    std.mem.writeInt(u16, hdr[2..4], @intCast(4 + body.len), .little);
    try writeAll(fd, &hdr);
    try writeAll(fd, body);
}

const Pkt = struct { id: u8, body: []const u8 };
fn bncsRecv(fd: Socket, buf: []u8) !Pkt {
    var hdr: [4]u8 = undefined;
    try readFull(fd, &hdr);
    if (hdr[0] != 0xFF) return error.BncsBadMagic;
    const len = std.mem.readInt(u16, hdr[2..4], .little);
    if (len < 4 or len > buf.len) return error.BncsBadLen;
    const blen = len - 4;
    try readFull(fd, buf[0..blen]);
    return .{ .id = hdr[1], .body = buf[0..blen] };
}

// little-endian 4CC: 'D2XP' is stored "PX2D", i.e. the chars reversed.
fn fourcc(s: []const u8) u32 {
    var v: u32 = 0;
    for (s) |c| v = (v << 8) | c; // big-endian of the chars == LE dword of reversed
    return v;
}

fn hexdump(label: []const u8, data: []const u8) void {
    std.debug.print("--- {s} ({d} bytes) ---\n", .{ label, data.len });
    var off: usize = 0;
    while (off < data.len) : (off += 16) {
        const row = data[off..@min(off + 16, data.len)];
        std.debug.print("{x:0>4}  ", .{off});
        for (0..16) |i| {
            if (i < row.len) std.debug.print("{x:0>2} ", .{row[i]}) else std.debug.print("   ", .{});
            if (i == 7) std.debug.print(" ", .{});
        }
        std.debug.print(" |", .{});
        for (row) |c| std.debug.print("{c}", .{if (c >= 0x20 and c < 0x7f) c else '.'});
        std.debug.print("|\n", .{});
    }
}

fn cstrAt(b: []const u8, off: usize) []const u8 {
    if (off >= b.len) return "";
    const end = std.mem.indexOfScalarPos(u8, b, off, 0) orelse b.len;
    return b[off..end];
}

const SID_AUTH_INFO = 0x50;
const SID_AUTH_CHECK = 0x51;
const SID_PING = 0x25;

const SID_CHECKAD = 0x15;
const SID_DISPLAYAD = 0x21;
const SID_GETFILETIME = 0x33;

extern "c" fn gettimeofday(tv: *std.posix.timeval, tz: ?*anyopaque) c_int;
fn unixNow() u32 {
    var tv: std.posix.timeval = undefined;
    _ = gettimeofday(&tv, null);
    return @intCast(tv.sec);
}

/// Options for `fetch`. proto_ver is the BNFTP version dword (default 0x0100).
/// bnftp_only is kept for parity with the CLI; fetch always uses a bare 0x02
/// connection and never runs the AUTH_INFO handshake, so it is informational.
///
/// banner_id / banner_ext address the *ad banner* store rather than the plain
/// file store: with both non-zero the server resolves the ad by id+extension,
/// which is a different key space from the filename (ad000001.smk by name is
/// refused). banner_ext is the extension as a 4CC, e.g. fourcc("smk").
pub const FetchOpts = struct {
    proto_ver: u16 = 0x0100,
    bnftp_only: bool = true,
    banner_id: u32 = 0,
    banner_ext: u32 = 0,
};

/// Open a fresh BNFTP (0x02) connection to host:port, request `filename` for
/// `product` (4CC, e.g. "D2XP"), read the whole reply, and return the file
/// payload bytes. Caller frees with `gpa`. Returns an empty slice if the server
/// reports the file as not hosted (fileSize == 0) or sends a short reply.
pub fn fetch(
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    product: []const u8,
    filename: []const u8,
    opts: FetchOpts,
    // Optional out: Blizzard's reported last-write time (Windows FILETIME, 100ns
    // ticks since 1601), read from the reply header. Left untouched on a miss.
    filetime_out: ?*u64,
) ![]u8 {
    const fd = try dial(gpa, host, port, null);
    defer _ = close(fd);

    var req: [512]u8 = undefined;
    const w = buildRequest(&req, product, filename, opts);

    try writeAll(fd, &[_]u8{0x02}); // BNFTP protocol selector
    try writeAll(fd, req[0..w]);

    // Read the reply (header + file) up to a cap (patches are ~10 MB). First get
    // the 8-byte prefix (hlen, fsize), then read until the full declared reply is
    // in hand. A short read - peer closed or the recv timeout elapsed mid-transfer
    // - is a truncation ERROR, not a valid file: returning a partial file silently
    // corrupts the archive (a truncated tos.txt looks like a fake divergence). The
    // caller retries on error.
    const cap = 64 << 20;
    const reply = try gpa.alloc(u8, cap);
    defer gpa.free(reply);
    var total: usize = 0;
    while (total < 8) {
        const n = readSome(fd, reply[total..]);
        if (n == 0) break;
        total += n;
    }
    if (total < 8) return gpa.alloc(u8, 0); // no header at all -> treat as not hosted

    const hlen = std.mem.readInt(u32, reply[0..4], .little);
    const fsize = std.mem.readInt(u32, reply[4..8], .little);
    if (fsize == 0) return gpa.alloc(u8, 0); // server reports the file as not hosted
    if (hlen < 0x18) return error.BnftpBadHeader;
    const need: usize = @as(usize, hlen) + fsize;
    if (need > cap) return error.BnftpReplyTooLarge;

    while (total < need) {
        const n = readSome(fd, reply[total..need]);
        if (n == 0) return error.BnftpTruncated; // closed/timed out before the full file
        total += n;
    }
    // Last-write time sits at header offset 0x10 (after headerLen, fileSize,
    // bannerId, bannerExt); hlen >= 0x18 guarantees these 8 bytes are present.
    if (filetime_out) |p| p.* = std.mem.readInt(u64, reply[0x10..0x18], .little);
    const out = try gpa.alloc(u8, fsize);
    @memcpy(out, reply[hlen..need]);
    return out;
}

/// Read only the BNFTP reply header for a request (no body). Returns the file
/// size the server reports — 0 means "not hosted" (also the short-reply case).
fn headProbe(
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    product: []const u8,
    filename: []const u8,
    opts: FetchOpts,
    name_out: *[128]u8,
    name_len: *usize,
) !u32 {
    const fd = try dial(gpa, host, port, null);
    defer _ = close(fd);
    var req: [512]u8 = undefined;
    const w = buildRequest(&req, product, filename, opts);
    try writeAll(fd, &[_]u8{0x02});
    try writeAll(fd, req[0..w]);

    var hb: [256]u8 = undefined;
    var got: usize = 0;
    while (got < hb.len) {
        const n = readSome(fd, hb[got..]);
        if (n == 0) break;
        got += n;
    }
    name_len.* = 0;
    if (got < 8) return 0;
    const hlen = std.mem.readInt(u32, hb[0..4], .little);
    const fsize = std.mem.readInt(u32, hb[4..8], .little);
    if (hlen >= 0x19 and got > 0x18) {
        const n = cstrAt(hb[0..got], 0x18);
        const cl = @min(n.len, name_out.len);
        @memcpy(name_out[0..cl], n[0..cl]);
        name_len.* = cl;
    }
    return fsize;
}

/// Serialize a BNFTPv1 request header into `buf`; returns its length.
fn buildRequest(buf: []u8, product: []const u8, filename: []const u8, opts: FetchOpts) usize {
    var w: usize = 2; // [0x00] reqLen u16, filled at the end
    std.mem.writeInt(u16, buf[w..][0..2], opts.proto_ver, .little);
    w += 2;
    std.mem.writeInt(u32, buf[w..][0..4], fourcc("IX86"), .little);
    w += 4;
    std.mem.writeInt(u32, buf[w..][0..4], fourcc(product), .little);
    w += 4;
    std.mem.writeInt(u32, buf[w..][0..4], opts.banner_id, .little);
    w += 4;
    std.mem.writeInt(u32, buf[w..][0..4], opts.banner_ext, .little);
    w += 4;
    std.mem.writeInt(u32, buf[w..][0..4], 0, .little);
    w += 4; // startPos
    std.mem.writeInt(u64, buf[w..][0..8], 0, .little);
    w += 8; // local filetime
    @memcpy(buf[w..][0..filename.len], filename);
    w += filename.len;
    buf[w] = 0;
    w += 1;
    std.mem.writeInt(u16, buf[0..2], @intCast(w), .little);
    return w;
}

/// Print a dword the way it sits on the wire (4CCs are stored reversed).
fn dwordChars(v: u32) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    for (&b) |*c| {
        if (c.* < 0x20 or c.* >= 0x7f) c.* = '.';
    }
    return b;
}

/// Open a BNCS (0x01) connection and complete SID_AUTH_INFO. The caller owns the
/// socket. `rx` is scratch for the reply.
fn bnetConnect(
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    product: []const u8,
    proxy: ?Proxy,
    rx: []u8,
) !Socket {
    const fd = try dial(gpa, host, port, proxy);
    errdefer _ = close(fd);
    try writeAll(fd, &[_]u8{0x01});

    var body: [128]u8 = undefined;
    var w: usize = 0;
    inline for (.{
        @as(u32, 0), fourcc("IX86"), fourcc(product), @as(u32, 0x0E),
        @as(u32, 0), @as(u32, 0),    @as(u32, 0),     @as(u32, 0),
        @as(u32, 0),
    }) |v| {
        std.mem.writeInt(u32, body[w..][0..4], v, .little);
        w += 4;
    }
    for ("USA\x00United States\x00") |c| {
        body[w] = c;
        w += 1;
    }
    try bncsSend(fd, SID_AUTH_INFO, body[0..w]);
    _ = try recvUntil(fd, rx, SID_AUTH_INFO);
    return fd;
}

/// Ask the server for its ad banner and download it.
///
/// The plain-filename BNFTP store does not hold ads (ad000001.smk by name gets
/// the not-hosted short reply). The real client path is:
///   SID_CHECKAD -> ad id + extension + filename + click URL
///   BNFTP with bannerId/bannerExt set -> the banner bytes
/// SID_GETFILETIME is swept too: the client uses it to resolve server-side files
/// by request id (0x1A tos, 0x80000001 version, 0x80000002 patcher, 0x80000003
/// adverts, 0x80000004 gateways, 0x80000005/6 extra work), so the adverts entry
/// names the ad file without guessing. Each probe gets its own connection —
/// real bnet drops the socket on a request it does not like, which would
/// otherwise poison every later step.
fn adsProbe(
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    product: []const u8,
    proxy: ?Proxy,
    out_dir: ?[]const u8,
) !void {
    checkAd(gpa, host, port, product, proxy, out_dir) catch |e|
        std.debug.print("[ads] CHECKAD path failed: {t}\n", .{e});
    fileTimeSweep(gpa, host, port, product, proxy) catch |e|
        std.debug.print("[ads] GETFILETIME sweep failed: {t}\n", .{e});
}

/// SID_GETFILETIME with an empty filename: the server answers with the file it
/// has for that request id. One connection per id — bnet closes the socket on a
/// request it rejects.
fn fileTimeSweep(
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    product: []const u8,
    proxy: ?Proxy,
) !void {
    std.debug.print("\n[ads] SID_GETFILETIME sweep\n", .{});
    const reqs = [_]struct { id: u32, name: []const u8 }{
        .{ .id = 0x1A, .name = "TermsOfService" },
        .{ .id = 0x80000001, .name = "Version" },
        .{ .id = 0x80000002, .name = "Patcher" },
        .{ .id = 0x80000003, .name = "Adverts" },
        .{ .id = 0x80000004, .name = "Gateways" },
        .{ .id = 0x80000005, .name = "ExtraWork1" },
        .{ .id = 0x80000006, .name = "ExtraWork2" },
    };
    for (reqs) |r| {
        var rx: [8192]u8 = undefined;
        const fd = bnetConnect(gpa, host, port, product, proxy, &rx) catch |e| {
            std.debug.print("  0x{x:0>8} {s:<14} connect failed ({t})\n", .{ r.id, r.name, e });
            continue;
        };
        defer _ = close(fd);
        var gb: [32]u8 = undefined;
        std.mem.writeInt(u32, gb[0..4], r.id, .little);
        std.mem.writeInt(u32, gb[4..8], 0, .little);
        std.mem.writeInt(u64, gb[8..16], 0, .little);
        gb[16] = 0; // empty filename: let the server name the file
        try bncsSend(fd, SID_GETFILETIME, gb[0..17]);
        const rep = recvUntil(fd, &rx, SID_GETFILETIME) catch |e| {
            std.debug.print("  0x{x:0>8} {s:<14} no reply ({t})\n", .{ r.id, r.name, e });
            continue;
        };
        const ft = if (rep.body.len >= 16) std.mem.readInt(u64, rep.body[8..16], .little) else 0;
        const nm = if (rep.body.len > 16) cstrAt(rep.body, 16) else "";
        std.debug.print("  0x{x:0>8} {s:<14} filetime={d} name=\"{s}\"\n", .{ r.id, r.name, ft, nm });
    }
}

fn checkAd(
    gpa: std.mem.Allocator,
    host: []const u8,
    port: u16,
    product: []const u8,
    proxy: ?Proxy,
    out_dir: ?[]const u8,
) !void {
    var rx: [8192]u8 = undefined;

    std.debug.print("\n[ads] SID_CHECKAD (product={s})\n", .{product});
    const fd = try bnetConnect(gpa, host, port, product, proxy, &rx);
    defer _ = close(fd);
    var cb: [16]u8 = undefined;
    std.mem.writeInt(u32, cb[0..4], fourcc("IX86"), .little);
    std.mem.writeInt(u32, cb[4..8], fourcc(product), .little);
    std.mem.writeInt(u32, cb[8..12], 0, .little); // id of last displayed banner
    std.mem.writeInt(u32, cb[12..16], unixNow(), .little);
    try bncsSend(fd, SID_CHECKAD, &cb);

    const ad = recvUntil(fd, &rx, SID_CHECKAD) catch |e| {
        // SocketClosed = the server dropped us (handler gone); a timeout means it
        // accepted the packet but has no ad to hand out.
        std.debug.print("  no SID_CHECKAD reply ({t}) — no ad for this product\n", .{e});
        return;
    };
    hexdump("SID_CHECKAD reply", ad.body);
    if (ad.body.len < 16) return;
    const ad_id = std.mem.readInt(u32, ad.body[0..4], .little);
    const ad_ext = std.mem.readInt(u32, ad.body[4..8], .little);
    const ad_ft = std.mem.readInt(u64, ad.body[8..16], .little);
    const ad_name = cstrAt(ad.body, 16);
    const ad_url = cstrAt(ad.body, 16 + ad_name.len + 1);
    std.debug.print("  adId=0x{x:0>8} ext=0x{x:0>8} \"{s}\" filetime={d}\n", .{ ad_id, ad_ext, dwordChars(ad_ext), ad_ft });
    std.debug.print("  filename=\"{s}\"  url=\"{s}\"\n", .{ ad_name, ad_url });
    if (ad_id == 0 or ad_name.len == 0) return;

    // Tell the server the banner was shown, exactly as a real client would.
    var db: [256]u8 = undefined;
    std.mem.writeInt(u32, db[0..4], fourcc("IX86"), .little);
    std.mem.writeInt(u32, db[4..8], fourcc(product), .little);
    std.mem.writeInt(u32, db[8..12], ad_id, .little);
    @memcpy(db[12..][0..ad_name.len], ad_name);
    db[12 + ad_name.len] = 0;
    try bncsSend(fd, SID_DISPLAYAD, db[0 .. 13 + ad_name.len]);

    const opts: FetchOpts = .{ .banner_id = ad_id, .banner_ext = ad_ext };
    const bytes = try fetch(gpa, host, port, product, ad_name, opts, null);
    std.debug.print("\n[ads] BNFTP banner \"{s}\": {d} bytes\n", .{ ad_name, bytes.len });
    if (bytes.len == 0) return;
    const out = if (out_dir) |d|
        try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ d, basename(ad_name) }, 0)
    else
        try std.fmt.allocPrintSentinel(gpa, "bnftp-{s}", .{basename(ad_name)}, 0);
    try writeFile(out.ptr, bytes);
    std.debug.print("  saved -> {s}\n", .{out});
}

/// Receive BNCS packets until one with id == want. Real bnet sends SID_PING
/// (0x25) on connect — echo its cookie back (servers gate further replies on it)
/// and keep reading. Unrelated packets are hexdumped and skipped.
fn recvUntil(fd: Socket, buf: []u8, want: u8) !Pkt {
    while (true) {
        const r = try bncsRecv(fd, buf);
        if (r.id == want) return r;
        if (r.id == SID_PING) {
            std.debug.print("  <- SID_PING, echoing cookie\n", .{});
            try bncsSend(fd, SID_PING, r.body);
            continue;
        }
        std.debug.print("  <- unexpected id=0x{x:0>2}, skipping\n", .{r.id});
        hexdump("skipped packet", r.body);
    }
}

// Entry point for the `bnftp` subcommand of the clientless binary (dispatched by
// main.zig). init.args = [clientless, "bnftp", <bnftp args...>].
pub fn run(init: std.process.Init.Minimal) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();

    var proxy: ?Proxy = null;
    var port: u16 = 6112;
    var proto_ver: u16 = 0x0100;
    var product: []const u8 = "D2XP";
    var out_dir: ?[]const u8 = null;
    var find_patch = false;
    var old_ver: u32 = 1; // deliberately-old EXE version to provoke "must upgrade"
    var head_only = false; // read only the BNFTP reply header (size), skip the body
    var bnftp_only = false; // skip the AUTH_INFO handshake (BNFTP needs no auth)
    var ads = false; // SID_CHECKAD -> download the ad banner by id+extension
    var ad_id: u32 = 0;
    var ad_ext: u32 = 0;
    var positional: [3][]const u8 = undefined;
    var npos: usize = 0;

    var it = std.process.Args.Iterator.init(init.args);
    _ = it.next(); // argv[0] (clientless)
    _ = it.next(); // "bnftp" subcommand
    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "--socks5")) {
            const hp = it.next() orelse return err("--socks5 wants HOST:PORT");
            const c = std.mem.lastIndexOfScalar(u8, hp, ':') orelse return err("--socks5 wants HOST:PORT");
            proxy = .{ .host = try gpa.dupe(u8, hp[0..c]), .port = try std.fmt.parseInt(u16, hp[c + 1 ..], 10) };
        } else if (std.mem.eql(u8, a, "--socks5-auth")) {
            const up = it.next() orelse return err("--socks5-auth wants USER:PASS");
            const c = std.mem.indexOfScalar(u8, up, ':') orelse return err("--socks5-auth wants USER:PASS");
            if (proxy) |*px| {
                px.user = try gpa.dupe(u8, up[0..c]);
                px.pass = try gpa.dupe(u8, up[c + 1 ..]);
            } else return err("--socks5-auth before --socks5");
        } else if (std.mem.eql(u8, a, "--port")) {
            port = try std.fmt.parseInt(u16, it.next() orelse return err("--port wants N"), 10);
        } else if (std.mem.eql(u8, a, "--proto-ver")) {
            proto_ver = try parseIntAuto(it.next() orelse return err("--proto-ver wants 0xNNNN"));
        } else if (std.mem.eql(u8, a, "--out-dir")) {
            out_dir = try gpa.dupe(u8, it.next() orelse return err("--out-dir wants DIR"));
        } else if (std.mem.eql(u8, a, "--find-patch")) {
            find_patch = true;
        } else if (std.mem.eql(u8, a, "--head")) {
            head_only = true;
        } else if (std.mem.eql(u8, a, "--bnftp-only")) {
            bnftp_only = true;
        } else if (std.mem.eql(u8, a, "--ads")) {
            ads = true;
        } else if (std.mem.eql(u8, a, "--ad-id")) {
            ad_id = try std.fmt.parseInt(u32, it.next() orelse return err("--ad-id wants N"), 0);
        } else if (std.mem.eql(u8, a, "--ad-ext")) {
            // "smk" -> the extension chars in wire order; 0xNNNNNNNN -> verbatim dword.
            const s = it.next() orelse return err("--ad-ext wants EXT|0xN");
            if (std.mem.startsWith(u8, s, "0x")) {
                ad_ext = try std.fmt.parseInt(u32, s, 0);
            } else {
                var eb: [4]u8 = .{ 0, 0, 0, 0 };
                @memcpy(eb[0..@min(4, s.len)], s[0..@min(4, s.len)]);
                ad_ext = std.mem.readInt(u32, &eb, .little);
            }
        } else if (std.mem.eql(u8, a, "--timeout")) {
            recv_timeout_ms = try std.fmt.parseInt(u32, it.next() orelse return err("--timeout wants MS"), 10);
        } else if (std.mem.eql(u8, a, "--old-ver")) {
            old_ver = try std.fmt.parseInt(u32, it.next() orelse return err("--old-ver wants N"), 0);
        } else if (npos < positional.len) {
            positional[npos] = try gpa.dupe(u8, a);
            npos += 1;
        }
    }
    if (npos == 0) return err("usage: bnftp-probe [opts] <target-host> [product] [filename]");
    const host = positional[0];
    if (npos >= 2) product = positional[1];
    const filename: ?[]const u8 = if (npos >= 3) positional[2] else null;

    if (proxy) |px| {
        std.debug.print("== via SOCKS5 {s}:{d}{s} ==\n", .{ px.host, px.port, if (px.user.len > 0) " (auth)" else "" });
    }
    std.debug.print("== target {s}:{d}  product={s}  protoVer=0x{x:0>4} ==\n", .{ host, port, product, proto_ver });

    if (ads) {
        try adsProbe(gpa, host, port, product, proxy, out_dir);
        std.debug.print("\ndone.\n", .{});
        return;
    }
    const fopts: FetchOpts = .{ .proto_ver = proto_ver, .banner_id = ad_id, .banner_ext = ad_ext };

    // ── Step 1: SID_AUTH_INFO to learn the MPQ filename (CD-key-free) ──
    // Skipped with --bnftp-only (BNFTP is unauthenticated; one conn per file).
    var rxbuf: [8192]u8 = undefined;
    var mpq_name_buf: [256]u8 = undefined;
    var mpq_name_len: usize = 0;
    if (!bnftp_only) {
        const fd = try dial(gpa, host, port, proxy);
        defer _ = close(fd);
        try writeAll(fd, &[_]u8{0x01}); // protocol selector

        var body: [128]u8 = undefined;
        var w: usize = 0;
        inline for (.{
            @as(u32, 0), // protocol id
            fourcc("IX86"), // platform
            fourcc(product), // product
            @as(u32, 0x0E), // version byte (D2)
            @as(u32, 0), // product language
            @as(u32, 0), // local IP
            @as(u32, 0), // tz bias
            @as(u32, 0), // locale id
            @as(u32, 0), // language id
        }) |v| {
            std.mem.writeInt(u32, body[w..][0..4], v, .little);
            w += 4;
        }
        for ("USA\x00United States\x00") |c| {
            body[w] = c;
            w += 1;
        }
        try bncsSend(fd, SID_AUTH_INFO, body[0..w]);

        const r = try recvUntil(fd, &rxbuf, SID_AUTH_INFO);
        std.debug.print("\n[1] SID_AUTH_INFO reply: id=0x{x:0>2}\n", .{r.id});
        hexdump("AUTH_INFO body", r.body);
        if (r.id == SID_AUTH_INFO and r.body.len >= 20) {
            const logon = std.mem.readInt(u32, r.body[0..4], .little);
            const stoken = std.mem.readInt(u32, r.body[4..8], .little);
            const filetime = std.mem.readInt(u64, r.body[12..20], .little);
            const fname = cstrAt(r.body, 20);
            const value = cstrAt(r.body, 20 + fname.len + 1);
            std.debug.print("  logonType=0x{x}  serverToken=0x{x:0>8}  mpqFiletime=0x{x}\n", .{ logon, stoken, filetime });
            std.debug.print("  MPQ filename = \"{s}\"\n", .{fname});
            std.debug.print("  value/formula = \"{s}\"\n", .{value});
            if (fname.len > 0 and fname.len < mpq_name_buf.len) {
                @memcpy(mpq_name_buf[0..fname.len], fname);
                mpq_name_len = fname.len;
            }
        } else {
            std.debug.print("  (unexpected reply id / too short — server may have changed the handshake)\n", .{});
        }

        // ── Optional: provoke the version gauntlet to reveal the forced patch ──
        // SID_AUTH_CHECK with an OLD exe version → result 0x100/0x102 "old version"
        // whose additional-info string is the patch file to BNFTP-download. This
        // is checked before CD-key validation, so still no key needed.
        if (find_patch) {
            var cb: [256]u8 = undefined;
            var cw: usize = 0;
            inline for (.{
                @as(u32, 0xCAFEBABE), // client token
                old_ver, // EXE version (old → "must upgrade")
                @as(u32, 0), // EXE hash (checkrevision result; wrong, irrelevant for ver-fail)
                @as(u32, 0), // number of CD keys in this packet
                @as(u32, 0), // using spawn key
            }) |v| {
                std.mem.writeInt(u32, cb[cw..][0..4], v, .little);
                cw += 4;
            }
            for ("Game.exe 04/14/15 22:07:36 4022272\x00probe\x00") |c| {
                cb[cw] = c;
                cw += 1;
            }
            try bncsSend(fd, SID_AUTH_CHECK, cb[0..cw]);
            const cr = try recvUntil(fd, &rxbuf, SID_AUTH_CHECK);
            std.debug.print("\n[1b] SID_AUTH_CHECK reply (old_ver=0x{x}):\n", .{old_ver});
            hexdump("AUTH_CHECK body", cr.body);
            if (cr.body.len >= 4) {
                const result = std.mem.readInt(u32, cr.body[0..4], .little);
                const info = cstrAt(cr.body, 4);
                std.debug.print("  result=0x{x:0>4}  additionalInfo=\"{s}\"\n", .{ result, info });
                std.debug.print("  ({s})\n", .{authCheckMeaning(result)});
                // For "old version" results the info string is the patch filename.
                if ((result == 0x100 or result == 0x102) and info.len > 0 and info.len < mpq_name_buf.len) {
                    @memcpy(mpq_name_buf[0..info.len], info);
                    mpq_name_len = info.len;
                    std.debug.print("  -> will BNFTP-download the patch: \"{s}\"\n", .{info});
                }
            }
        }
    }

    const file_to_get = filename orelse (if (mpq_name_len > 0) mpq_name_buf[0..mpq_name_len] else return err("no filename: AUTH_INFO gave none and none passed on cmdline"));

    // ── Step 2: BNFTP download (0x02 connection, unauthenticated) ──
    // Common path (no proxy, full body): use the reusable fetch() helper.
    if (proxy == null and !head_only) {
        var filetime: u64 = 0;
        const body = try fetch(gpa, host, port, product, file_to_get, fopts, &filetime);
        std.debug.print("\n[2] BNFTP fetched \"{s}\": {d} file bytes (filetime={d})\n", .{ file_to_get, body.len, filetime });
        const out = if (out_dir) |d|
            try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ d, basename(file_to_get) }, 0)
        else
            try std.fmt.allocPrintSentinel(gpa, "bnftp-{s}", .{basename(file_to_get)}, 0);
        try writeFile(out.ptr, body);
        std.debug.print("  saved {d} file bytes -> {s}\n", .{ body.len, out });
        if (body.len >= 4) std.debug.print("  first 4 file bytes: {x:0>2} {x:0>2} {x:0>2} {x:0>2} (MPQ magic 'MPQ\\x1a' = 4d 50 51 1a)\n", .{ body[0], body[1], body[2], body[3] });
        std.debug.print("\ndone.\n", .{});
        return;
    }

    {
        const fd = try dial(gpa, host, port, proxy);
        defer _ = close(fd);

        var req: [512]u8 = undefined;
        const w = buildRequest(&req, product, file_to_get, fopts);

        try writeAll(fd, &[_]u8{0x02}); // BNFTP protocol selector
        try writeAll(fd, req[0..w]);
        std.debug.print("\n[2] BNFTP request for \"{s}\" ({d}-byte header)\n", .{ file_to_get, w });
        if (!head_only) hexdump("BNFTP request", req[0..w]);

        // --head: read only enough for the reply header (size + name), then stop.
        // The reply leads with u32 headerLen, u32 fileSize — so existence/size is
        // known without pulling the (multi-MB) body. Good for sweeping filenames.
        if (head_only) {
            var hb: [256]u8 = undefined;
            var got: usize = 0;
            while (got < hb.len) {
                const n = readSome(fd, hb[got..]);
                if (n == 0) break;
                got += n;
            }
            if (got >= 8) {
                const hlen = std.mem.readInt(u32, hb[0..4], .little);
                const fsize = std.mem.readInt(u32, hb[4..8], .little);
                const rname = if (hlen >= 0x19 and 0x18 < got) cstrAt(hb[0..got], 0x18) else "";
                std.debug.print("  HEAD: fileSize={d}  headerLen={d}  name=\"{s}\"  {s}\n", .{ fsize, hlen, rname, if (fsize == 0) "NOT HOSTED" else "EXISTS" });
            } else {
                std.debug.print("  HEAD: short reply ({d} bytes) — not hosted\n", .{got});
            }
            std.debug.print("\ndone.\n", .{});
            return;
        }

        // Read the whole reply (header + file) up to a cap (patches are ~10 MB).
        const cap = 64 << 20;
        const reply = try gpa.alloc(u8, cap);
        var total: usize = 0;
        while (total < cap) {
            const n = readSome(fd, reply[total..]);
            if (n == 0) break;
            total += n;
        }
        const data = reply[0..total];
        std.debug.print("\n[2] BNFTP reply: {d} bytes total\n", .{total});
        hexdump("BNFTP reply header (first 64)", data[0..@min(64, data.len)]);

        if (data.len >= 8) {
            const hlen = std.mem.readInt(u32, data[0..4], .little);
            const fsize = std.mem.readInt(u32, data[4..8], .little);
            std.debug.print("  parsed: headerLen={d}  fileSize={d}\n", .{ hlen, fsize });
            if (hlen >= 0x18 and hlen <= data.len) {
                const ftime = std.mem.readInt(u64, data[0x10..0x18], .little);
                const rname = cstrAt(data, 0x18);
                std.debug.print("  filetime=0x{x}  filename=\"{s}\"\n", .{ ftime, rname });
                const body = data[hlen..];
                // Save the file payload for inspection.
                // With --out-dir, store under the real filename (drop straight
                // into realmd-data/bnftp/ so our server serves the authentic file).
                // Otherwise save to cwd as bnftp-<name> for ad-hoc inspection.
                const out = if (out_dir) |d|
                    try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ d, basename(file_to_get) }, 0)
                else
                    try std.fmt.allocPrintSentinel(gpa, "bnftp-{s}", .{basename(file_to_get)}, 0);
                try writeFile(out.ptr, body[0..@min(body.len, fsize)]);
                std.debug.print("  saved {d} file bytes -> {s}\n", .{ @min(body.len, fsize), out });
                if (body.len >= 4) std.debug.print("  first 4 file bytes: {x:0>2} {x:0>2} {x:0>2} {x:0>2} (MPQ magic 'MPQ\\x1a' = 4d 50 51 1a)\n", .{ body[0], body[1], body[2], body[3] });
            } else {
                std.debug.print("  headerLen 0x{x} out of range — dumping more:\n", .{hlen});
                hexdump("BNFTP reply (first 256)", data[0..@min(256, data.len)]);
            }
        }
    }
    std.debug.print("\ndone.\n", .{});
}

fn authCheckMeaning(result: u32) []const u8 {
    return switch (result) {
        0x000 => "passed",
        0x100 => "old game version (info = patch file)",
        0x101 => "invalid version",
        0x102 => "game version must be downgraded (info = patch file)",
        0x200 => "invalid CD key",
        0x201 => "CD key in use",
        0x202 => "banned key",
        0x203 => "wrong product",
        else => "unknown / version-code in low byte",
    };
}

fn basename(p: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfAny(u8, p, "/\\") orelse return p;
    return p[slash + 1 ..];
}

fn parseIntAuto(s: []const u8) !u16 {
    if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X"))
        return std.fmt.parseInt(u16, s[2..], 16);
    return std.fmt.parseInt(u16, s, 10);
}

fn err(msg: []const u8) anyerror {
    std.debug.print("error: {s}\n", .{msg});
    return error.BadUsage;
}
