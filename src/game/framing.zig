//! S->C framing, and the one thing about it that is not the same on every engine.
//!
//! libd2 carries 1.14d's size table, which is right for every expansion build. Classic differs in
//! exactly one entry: `0x01` GameFlags is SEVEN bytes there against eight everywhere else. Framed
//! as eight it swallows the `0x02` LoadSuccess sitting behind it, and the client then waits
//! forever for a handshake the server already sent — a hang with nothing in the log to explain it.
//!
//! This lives in its own file, and takes the era as an argument rather than reading a global,
//! because the whole failure mode is one table entry being wrong for one family of builds. That is
//! worth being able to assert on directly.
const std = @import("std");
const sc = @import("libd2").net.sc;

/// Which S->C table a server speaks. Classic covers 1.00-1.06b; every expansion build is `lod`.
pub const Era = enum {
    classic,
    lod,

    /// The product code a client announces IS the statement of which one it is talking to: D2DV is
    /// classic, D2XP is expansion. Anything else is treated as expansion, since that is what every
    /// build from 1.07 on speaks.
    pub fn fromProduct(product: []const u8) Era {
        return if (std.mem.eql(u8, product, "D2DV")) .classic else .lod;
    }
};

/// Length of the packet at the head of `buf`, or null when more bytes are needed to tell.
/// Zero means the opcode is unknown and the stream cannot be resynchronised.
pub fn packetSize(era: Era, buf: []const u8) ?usize {
    if (era == .classic and buf.len >= 1 and buf[0] == 0x01) {
        return if (buf.len >= 7) 7 else null;
    }
    return sc.packetSize(buf);
}

test "0x01 GameFlags is seven bytes on classic and eight on expansion" {
    const wire = [_]u8{ 0x01, 1, 2, 3, 4, 5, 6, 7 };
    try std.testing.expectEqual(@as(?usize, 7), packetSize(.classic, &wire));
    try std.testing.expectEqual(@as(?usize, 8), packetSize(.lod, &wire));
}

test "classic does not swallow the 0x02 LoadSuccess riding behind GameFlags" {
    // The exact shape that hung 1.06b: GameFlags and LoadSuccess arriving in one read.
    const wire = [_]u8{ 0x01, 1, 2, 3, 4, 5, 6, 0x02 };

    const first = packetSize(.classic, &wire).?;
    try std.testing.expectEqual(@as(usize, 7), first);
    // The byte after it must still be seen as its own packet, not eaten as GameFlags' eighth.
    try std.testing.expectEqual(@as(u8, 0x02), wire[first]);
    try std.testing.expectEqual(@as(?usize, 1), packetSize(.classic, wire[first..]));

    // Read with the expansion table, the same bytes are ONE packet and LoadSuccess is lost —
    // which is the bug, asserted so it cannot come back unnoticed.
    try std.testing.expectEqual(@as(?usize, 8), packetSize(.lod, &wire));
}

test "a partial GameFlags asks for more bytes rather than guessing, in both eras" {
    const six = [_]u8{ 0x01, 1, 2, 3, 4, 5 };
    try std.testing.expectEqual(@as(?usize, null), packetSize(.classic, &six));
    try std.testing.expectEqual(@as(?usize, null), packetSize(.lod, &six));
    try std.testing.expectEqual(@as(?usize, null), packetSize(.classic, &[_]u8{}));
}

test "every other opcode is framed identically in both eras" {
    // 0x01 is the ONLY divergence. If a second one ever appears this fails and says so, rather
    // than the client quietly desynchronising against one family of servers.
    var buf: [64]u8 = [_]u8{0} ** 64;
    var op: usize = 0;
    while (op <= 0xff) : (op += 1) {
        if (op == 0x01) continue;
        buf[0] = @intCast(op);
        try std.testing.expectEqual(packetSize(.lod, &buf), packetSize(.classic, &buf));
    }
}

test "the product code decides the era" {
    try std.testing.expectEqual(Era.classic, Era.fromProduct("D2DV"));
    try std.testing.expectEqual(Era.lod, Era.fromProduct("D2XP"));
    // Not a classic product, so framed the way every 1.07+ build speaks.
    try std.testing.expectEqual(Era.lod, Era.fromProduct(""));
}
