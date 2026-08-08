//! A game session: the socket, the stream, and the world it describes.
//!
//! Everything below the bot. `d2-client` knows how to turn a packet into world state and how to
//! turn an intention into a command; it deliberately never touches a socket. This is the part that
//! does — connect, greet, frame, pump, send — and it is here rather than in libd2 because the
//! transport is the client's business, not the engine's.
//!
//! Only AF00 (compression off) is supported, and that is a ruling rather than a gap.
//!
//! The 0xAF greeting flag selects the Huffman codec and the framing TOGETHER, because they are the
//! same branch: `SendPacketToClient` @0x52b330 writes the length prefix on the compressed path
//! only. So AF00 is raw AND unframed — after the 2-byte greeting the stream is a bare run of S->C
//! packets, and the per-opcode size table is the only thing that says where each one ends. AF01 is
//! Huffman AND length-prefixed. There is no mix, and half-supporting the second dialect is how you
//! get a stream that decodes for ten packets and then desyncs.

const std = @import("std");
const sc = @import("d2-net").sc;
const client = @import("d2-client");
const World = client.World;
const Actor = client.Actor;

// ── libc sockets. std.net is gone in 0.16, and this is the one place that needs them. ──
pub const Socket = c_int;
extern "c" fn socket(domain: c_int, sock_type: c_int, protocol: c_int) c_int;
extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: c_uint) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn setsockopt(fd: c_int, level: c_int, optname: c_int, optval: *const anyopaque, optlen: c_uint) c_int;
extern "c" fn gettimeofday(tv: *std.posix.timeval, tz: ?*anyopaque) c_int;
const SOCK_STREAM: c_int = 1;

pub const POLLIN: i16 = 0x0001;
pub const pollfd = extern struct { fd: c_int, events: i16, revents: i16 };
pub extern "c" fn poll(fds: *pollfd, nfds: c_uint, timeout: c_int) c_int;

pub fn setRecvTimeout(fd: Socket, ms: u32) void {
    const tv = std.posix.timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    _ = setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, &tv, @sizeOf(std.posix.timeval));
}

pub fn nowMs() i64 {
    var tv: std.posix.timeval = undefined;
    _ = gettimeofday(&tv, null);
    return @as(i64, @intCast(tv.sec)) * 1000 + @divTrunc(@as(i64, @intCast(tv.usec)), 1000);
}

pub fn writeAll(fd: Socket, buf: []const u8) !void {
    var sent: usize = 0;
    while (sent < buf.len) {
        const n = write(fd, buf.ptr + sent, buf.len - sent);
        if (n <= 0) return error.WriteFailed;
        sent += @intCast(n);
    }
}

pub fn connectResolved(gpa: std.mem.Allocator, host: []const u8, port: u16) !Socket {
    const chost = try gpa.dupeZ(u8, host);
    defer gpa.free(chost);
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

/// Where to join, and as whom.
///
/// This is the direct-to-GS join: straight to the game port with the game already created, which
/// is what the standalone host and a qqserver-fronted engine GS both accept. The BNCS/MCP realm
/// login that produces `game_id` for a real realm is a separate leg and lives in the CLI.
pub const JoinOptions = struct {
    host: []const u8,
    port: u16,
    /// Resolves the game on the far side — the u16 token the realm handed out (MCP JOINGAME).
    game_id: u16,
    /// The nGameHash the same JOINGAME reply carried. Zero for hosts that do not check it.
    game_hash: u32 = 0,
    character: []const u8,
    /// nCharClass, as CharStats.txt orders them.
    char_class: u8 = 1,
    /// How long to wait for the server to say it is ready for us.
    ready_timeout_ms: i64 = 15000,
    /// How long to wait for the server's 0xAF greeting before sending GAMELOGON anyway.
    greet_timeout_ms: i64 = 5000,
};

/// Told about every packet as it is applied, before the world sees it.
pub const Observer = struct {
    ctx: *anyopaque,
    on_packet: *const fn (ctx: *anyopaque, packet: []const u8) void,
};

pub const Session = struct {
    gpa: std.mem.Allocator,
    fd: Socket,
    world: World,
    observer: ?Observer = null,

    /// Bytes read but not yet forming a whole packet.
    buf: []u8,
    len: usize = 0,
    /// The unframed 2-byte 0xAF greeting has been consumed; everything after it is framed.
    greeted: bool = false,
    /// The server has streamed LoadSuccess and we have answered with ENTERGAME.
    entered: bool = false,
    closed: bool = false,

    pub const Error = error{
        ConnectFailed,
        ResolveFailed,
        WriteFailed,
        CompressionNotSupported,
        NeverReady,
        Disconnected,
        OutOfMemory,
    };

    pub fn open(gpa: std.mem.Allocator, opts: JoinOptions) !Session {
        const fd = try connectResolved(gpa, opts.host, opts.port);
        errdefer _ = close(fd);
        // Short so the caller's loop keeps ticking on a quiet server rather than blocking in read().
        setRecvTimeout(fd, 50);

        var self = Session{
            .gpa = gpa,
            .fd = fd,
            .world = World.init(gpa),
            .buf = try gpa.alloc(u8, 64 * 1024),
        };
        errdefer self.deinit();
        self.world.expectLocalPlayer(opts.character);

        self.awaitGreeting(opts.greet_timeout_ms);
        try self.sendGameLogon(opts);
        return self;
    }

    /// Let the server greet first, if it is going to.
    ///
    /// The real engine sends its 0xAF greeting unprompted and the client answers with GAMELOGON;
    /// a host that expects GAMELOGON first is happy either way, so waiting costs nothing and
    /// speaking out of turn on the engine costs the whole join. After the timeout we send anyway,
    /// which is what a real client does.
    fn awaitGreeting(self: *Session, timeout_ms: i64) void {
        const deadline = nowMs() + timeout_ms;
        while (!self.greeted and nowMs() < deadline) {
            var pfd = pollfd{ .fd = self.fd, .events = POLLIN, .revents = 0 };
            if (poll(&pfd, 1, 50) <= 0 or (pfd.revents & POLLIN) == 0) continue;
            const nr = read(self.fd, self.buf[self.len..].ptr, self.buf.len - self.len);
            if (nr <= 0) return;
            self.len += @intCast(nr);
            if (self.len >= 2 and self.buf[0] == 0xAF) {
                self.greeted = true;
                std.mem.copyForwards(u8, self.buf[0 .. self.len - 2], self.buf[2..self.len]);
                self.len -= 2;
            }
        }
    }

    /// GAMELOGON (0x68), 37 bytes — `D2GSPacketClt0x68`, packed and raw.
    ///
    /// Every field matters on the real engine even though a simpler host ignores most of them: the
    /// hash and token identify the game the realm assigned, and the two constants are the
    /// expansion/version pair the engine checks before it will admit anyone.
    fn sendGameLogon(self: *Session, opts: JoinOptions) !void {
        var gl: [37]u8 = [_]u8{0} ** 37;
        gl[0] = 0x68;
        std.mem.writeInt(u32, gl[1..5], opts.game_hash, .little); // nGameHash (from JOINGAME)
        std.mem.writeInt(u16, gl[5..7], opts.game_id, .little); // nGameToken
        gl[7] = opts.char_class; // nCharClass
        std.mem.writeInt(u32, gl[8..12], 0x0e, .little); // nVerByte — GetGameVersion(), 1.14d
        std.mem.writeInt(u32, gl[12..16], 0xed5fcc50, .little); // nVersionConstant (expansion)
        std.mem.writeInt(u32, gl[16..20], 0x91a519b6, .little); // nConstant
        gl[20] = 0; // nLanguageCode
        const n = @min(opts.character.len, 16);
        @memcpy(gl[21..][0..n], opts.character[0..n]);
        try writeAll(self.fd, &gl);
    }

    pub fn deinit(self: *Session) void {
        if (!self.closed) {
            _ = close(self.fd);
            self.closed = true;
        }
        self.world.deinit();
        self.gpa.free(self.buf);
    }

    pub fn actor(self: *Session) Actor {
        return .{ .world = &self.world };
    }

    /// Send a client command. `d2-client`'s Actor produces these; nothing here interprets them.
    pub fn send(self: *Session, bytes: []const u8) !void {
        if (self.closed) return Error.Disconnected;
        try writeAll(self.fd, bytes);
    }

    /// Leave the game properly.
    ///
    /// Worth doing even when the process is about to exit. A client that just drops its socket
    /// leaves the character in the game as far as the server is concerned, and the NEXT join for
    /// that character is then accepted and streamed nothing — a silent failure that looks exactly
    /// like a broken world load, and one that costs an afternoon to recognise the second time.
    pub fn leave(self: *Session) void {
        if (self.closed) return;
        writeAll(self.fd, &[_]u8{0x69}) catch {};
        _ = close(self.fd);
        self.closed = true;
    }

    pub const Tick = struct {
        /// Packets applied to the world this tick.
        applied: u32 = 0,
        /// The server said it is ready and we answered — the world burst follows.
        entered_now: bool = false,
        /// The peer hung up.
        eof: bool = false,
    };

    /// Read what is available, apply it, and answer the handshake. Returns after at most
    /// `budget_ms` whether or not anything arrived, so a caller's own loop keeps its cadence.
    pub fn pump(self: *Session, budget_ms: i32) !Tick {
        var tick = Tick{};
        if (self.closed) {
            tick.eof = true;
            return tick;
        }

        var pfd = pollfd{ .fd = self.fd, .events = POLLIN, .revents = 0 };
        const pr = poll(&pfd, 1, budget_ms);
        if (pr > 0 and (pfd.revents & POLLIN) != 0) {
            const nr = read(self.fd, self.buf[self.len..].ptr, self.buf.len - self.len);
            if (nr == 0) {
                tick.eof = true;
                self.closed = true;
                return tick;
            }
            if (nr > 0) self.len += @intCast(nr);
        }

        var off: usize = 0;
        while (off < self.len) {
            if (!self.greeted) {
                if (self.len - off < 2) break;
                if (self.buf[off] == 0xAF) {
                    // The greeting is the one unframed packet in EITHER dialect, and its flag says
                    // which dialect the rest of the stream is. AF01 is Huffman + length-prefixed;
                    // we do not speak it, and guessing would desync rather than fail.
                    if (self.buf[off + 1] != 0x00) return Error.CompressionNotSupported;
                    self.greeted = true;
                    off += 2;
                    continue;
                }
                self.greeted = true; // no greeting on this dialect — read it as raw from here
            }
            const n = sc.packetSize(self.buf[off..self.len]) orelse break; // need more bytes
            if (n == 0) {
                // An opcode the size table does not know. There is no length to skip by, so the
                // rest of this read is unreadable; resync a byte rather than pretending.
                off += 1;
                continue;
            }
            if (off + n > self.len) break; // whole packet not here yet
            const pkt = self.buf[off .. off + n];
            if (self.observer) |o| o.on_packet(o.ctx, pkt);
            self.world.apply(pkt);
            tick.applied += 1;

            // What drives ENTERGAME is NOT GameFlags (0x01): the client's Incoming0x01_GameFlags
            // handler only sets difficulty, expansion and UI state. `CLIENT_SendGameFlagsAndSetState1`
            // sends GameFlags and THEN a bare StateCommand(0) — and it is that 0x00 the real client
            // answers. The 1.14d engine additionally leads with HandShake (0x0b) and wants 0x6b
            // before it will stream anything at all; 0x02 is kept for hosts that echo a LoadSuccess.
            //
            // Answering on 0x01 is one packet too early, and the engine's reply to that is not an
            // error — it sends its game-info packets and then simply never streams the act.
            if ((pkt[0] == 0x00 or pkt[0] == 0x02 or pkt[0] == 0x0b) and !self.entered) {
                try writeAll(self.fd, &[_]u8{ 0x6a, 0x6b });
                self.entered = true;
                tick.entered_now = true;
            }
            off += n;
        }
        if (off > 0) {
            std.mem.copyForwards(u8, self.buf[0 .. self.len - off], self.buf[off..self.len]);
            self.len -= off;
        }
        return tick;
    }

    /// Pump until we are in the game and the act has streamed, or give up.
    pub fn waitUntilInGame(self: *Session, timeout_ms: i64) !void {
        const deadline = nowMs() + timeout_ms;
        while (nowMs() < deadline) {
            const tick = try self.pump(50);
            if (tick.eof) return Error.Disconnected;
            if (self.entered and self.world.local_player_guid != null) return;
        }
        return Error.NeverReady;
    }
};
