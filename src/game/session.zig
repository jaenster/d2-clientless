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
const sc = @import("libd2").net.sc;
const cs = @import("libd2").net.cs;
const client = @import("libd2").client;
const World = client.World;
const Actor = client.Actor;

const net = @import("d2-net-socket");

// The socket layer is shared with the realm leg — one connect, one timeout policy, one place to
// change them. Re-exported because callers of a session shouldn't need to know it exists.
pub const Socket = net.Socket;
pub const POLLIN = net.POLLIN;
pub const pollfd = net.pollfd;
pub const poll = net.poll;
pub const setRecvTimeout = net.setRecvTimeout;
pub const nowMs = net.nowMs;
pub const writeAll = net.writeAll;
pub const connectResolved = net.connectResolved;

const read = net.read;
const close = net.close;

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

/// A server-sent end to the connection. `ConnectionTerminated` (0xB0) carries nothing — the
/// engine sends it when it could not seat the client, a full game being the ordinary reason.
/// `ConnectionRefused` (0xB4) carries a load-error code.
pub const Refusal = struct {
    pub const TERMINATED: u8 = 0xB0;
    pub const REFUSED: u8 = 0xB4;

    opcode: u8,
    reason: u32 = 0,

    pub fn describe(self: Refusal) []const u8 {
        if (self.opcode == TERMINATED) return "the server could not seat us (0xB0; the game is full, or it would not take another client)";
        return switch (self.reason) {
            0x13, 0x14, 0x15 => "hardcore (0xB4)",
            0x17, 0x18 => "expansion mismatch (0xB4)",
            else => "the server refused the character (0xB4)",
        };
    }
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
    /// Bytes skipped across the whole session because no opcode framed there. Non-zero means the
    /// S->C stream desynced and everything after it is guesswork.
    resynced: u32 = 0,
    /// The server has streamed LoadSuccess and we have answered with ENTERGAME.
    entered: bool = false,
    /// The server said it was ending this connection, and why.
    ///
    /// Worth keeping, because the alternative is reporting every one of these as "disconnected".
    /// A game with no room left for another client answers 0xB0 and hangs up — one byte, easy to
    /// read as noise — and a character the server will not load answers 0xB4 with the reason in
    /// it. Both look exactly like a socket that died on its own if nobody writes them down, and
    /// "the connection dropped" sends you looking at the network for an answer the server already
    /// gave you.
    refused: ?Refusal = null,
    /// When the next keep-alive ping is due.
    next_ping: i64 = 0,
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
    /// How long to keep reading after LEAVEGAME before giving up on the server's own hang-up.
    pub const LEAVE_GRACE_MS: i64 = 1000;

    pub fn leave(self: *Session) void {
        if (self.closed) return;
        writeAll(self.fd, &[_]u8{0x69}) catch {};
        // Then WAIT for the server to hang up. Sending the byte and closing in the same breath
        // races the engine: it sees the dead socket first and takes its dropped-connection path
        // instead, which leaves the character seated in the game it just left. The next join for
        // that character then has to evict it, and if that eviction loses its own race the join is
        // refused with nothing said. The server closes as soon as it has torn us down, so reading
        // to EOF is both the acknowledgement and the wait.
        const deadline = nowMs() + LEAVE_GRACE_MS;
        var sink: [512]u8 = undefined;
        while (nowMs() < deadline) {
            var pfd = pollfd{ .fd = self.fd, .events = POLLIN, .revents = 0 };
            if (poll(&pfd, 1, 50) <= 0) continue;
            if (read(self.fd, &sink, sink.len) <= 0) break; // EOF: torn down
        }
        _ = close(self.fd);
        self.closed = true;
    }

    /// How often to ping. The engine drops a connection that goes quiet.
    pub const PING_INTERVAL_MS: i64 = 2000;

    /// SCMD 0x6d — the client keep-alive. Thirteen bytes: opcode, a tick count, and eight zeros.
    ///
    /// Session-layer, like GAMELOGON and ENTERGAME: it is not in the server's command dispatch
    /// table, which is exactly why a client that only ever sends game commands looks idle. The
    /// engine hangs up on a connection that stops pinging, and it does so without saying anything,
    /// so the symptom is a socket that simply closes.
    ///
    /// The LENGTH is the part that has to be exact. The server frames C->S by the same size table
    /// the client does, so a short 0x6d does not get rejected — it gets sized at 13 anyway, eating
    /// the eight bytes that follow it. Every command after the first ping is then read at an offset,
    /// and the game goes silent rather than erroring. `PING_SIZE` is asserted against the engine's
    /// own table below so it cannot drift back.
    const PING_SIZE = 13;

    fn ping(self: *Session) void {
        var buf: [PING_SIZE]u8 = [_]u8{0} ** PING_SIZE;
        buf[0] = 0x6d;
        std.mem.writeInt(u32, buf[1..5], @truncate(@as(u64, @bitCast(nowMs()))), .little);
        writeAll(self.fd, &buf) catch {};
        self.next_ping = nowMs() + PING_INTERVAL_MS;
    }

    pub const Tick = struct {
        /// Packets applied to the world this tick.
        applied: u32 = 0,
        /// Bytes skipped because no opcode framed there.
        ///
        /// A desync has no error to report — the stream simply stops meaning anything, and the
        /// world model quietly stops being updated while every command we send is computed from
        /// the last position we understood. Counting the skips is the only way to tell that apart
        /// from a character that genuinely will not move.
        resynced: u32 = 0,
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

        if (nowMs() >= self.next_ping) self.ping();

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
                tick.resynced += 1;
                self.resynced +|= 1;
                continue;
            }
            if (off + n > self.len) break; // whole packet not here yet
            const pkt = self.buf[off .. off + n];
            if (self.observer) |o| o.on_packet(o.ctx, pkt);
            self.world.apply(pkt);
            tick.applied += 1;
            if (pkt[0] == Refusal.TERMINATED) self.refused = .{ .opcode = pkt[0] };
            if (pkt[0] == Refusal.REFUSED and pkt.len >= 5)
                self.refused = .{ .opcode = pkt[0], .reason = std.mem.readInt(u32, pkt[1..5], .little) };

            // What drives ENTERGAME is NOT GameFlags (0x01): the client's Incoming0x01_GameFlags
            // handler only sets difficulty, expansion and UI state. `CLIENT_SendGameFlagsAndSetState1`
            // sends GameFlags and THEN a bare StateCommand(0) — and it is that 0x00 the real client
            // answers. The 1.14d engine additionally leads with HandShake (0x0b) and wants 0x6b
            // before it will stream anything at all; 0x02 is kept for hosts that echo a LoadSuccess.
            //
            // Answering on 0x01 is one packet too early, and the engine's reply to that is not an
            // error — it sends its game-info packets and then simply never streams the act.
            if ((pkt[0] == 0x00 or pkt[0] == 0x02 or pkt[0] == 0x0b) and !self.entered) {
                // 0x6A then 0x6B. The engine's own client never sends 0x6A
                // (`NET_D2GS_CLIENT_Send_0x6A` @0x478010 has no callers) and the ping is 0x6D, so
                // the "0x6A = ping" label this carried is wrong — but dropping it stopped the world
                // from streaming here, and an unexplained-but-working handshake beats a tidy one
                // that hangs. Left in place until something explains what the GS does with it.
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
    ///
    /// "In the game" is not "our character exists". The server names the player before it says
    /// where the player IS: CreatePlayer arrives first, LoadAct with the level and the map seed
    /// after it. Returning on the first of those hands the caller an area of 0 and a seed of 0,
    /// and anything that generates the world from that seed generates the wrong world — silently,
    /// because zero is a perfectly valid-looking seed.
    ///
    /// A non-zero map seed is what says LoadAct has been seen; nothing else sets it. The position
    /// is the last of the three to arrive, and it matters for the same reason: a route planned
    /// from (0,0) is a route from the corner of the map.
    pub fn waitUntilInGame(self: *Session, timeout_ms: i64) !void {
        const deadline = nowMs() + timeout_ms;
        while (nowMs() < deadline) {
            const tick = try self.pump(50);
            if (tick.eof) return Error.Disconnected;
            if (!self.entered or self.world.local_player_guid == null) continue;
            if (!(self.world.loaded or self.world.map_seed != 0)) continue;
            const at = self.world.playerPos() orelse continue;
            if (at.x != 0 or at.y != 0) return;
        }
        return Error.NeverReady;
    }
};

test "the keep-alive is the size the engine's own C->S table says it is" {
    // A short ping is not rejected, it is misframed — the eight bytes after it are swallowed as
    // part of the packet and every command from then on is read at an offset.
    try std.testing.expectEqual(@as(usize, Session.PING_SIZE), cs.sizeOf(&[_]u8{0x6d} ** 16).?);
    try std.testing.expectEqual(@as(usize, 37), cs.sizeOf(&[_]u8{0x68} ** 40).?);
    try std.testing.expectEqual(@as(usize, 1), cs.sizeOf(&[_]u8{0x69}).?); // leave
}
