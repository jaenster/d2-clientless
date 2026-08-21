//! Which build's S->C size table this client frames with, and how it is chosen.
//!
//! The table itself lives in libd2 (`net.sc_versions`), read out of each build's own D2Net.dll.
//! This file is only the choice, and the choice is the part that used to be wrong: it was a
//! two-value `classic`/`lod` split with one hand-found divergence, inferred from debugging a hang
//! rather than read from a binary. Both halves of it turned out to be wrong. `0x01` GameFlags is
//! SIX bytes on 1.06b, not the seven the classic branch used, and SEVEN on 1.07 through 1.09,
//! which the `lod` branch framed as eight. So every build before 1.10f desynced on the first
//! packet of the handshake, which is why none of them has ever been driven to a world.
//!
//! There is no negotiation to lean on here — nothing in the stream announces the build — so the
//! caller has to say. An unmeasured build is an error rather than a guess at its neighbour's
//! table, because guessing is what produced a hang with nothing in the log to explain it.
const std = @import("std");
const sc_versions = @import("libd2").net.sc_versions;

pub const Version = sc_versions.Version;

/// The build named on the command line, or null when nobody has read that build's table yet.
///
/// Every one of these is its own measurement. 1.13c is worth pointing at: it used to be mapped to
/// 1.14d's table because a world had been decoded through it, and that worked — but its table is
/// 182 entries against 1.14d's 181, so "it worked" was luck about which opcodes turned up rather
/// than the two being the same.
pub fn fromEngine(name: []const u8) ?Version {
    const map = .{
        .{ "1.06b", Version.v106b },
        .{ "1.07", Version.v107 },
        .{ "1.08", Version.v108 },
        .{ "1.09b", Version.v109b },
        .{ "1.09d", Version.v109d },
        .{ "1.10f", Version.v110f },
        .{ "1.13c", Version.v113c },
        .{ "1.14d", Version.v114d },
    };
    inline for (map) |e| {
        if (std.mem.eql(u8, name, e[0])) return e[1];
    }
    return null;
}

/// Length of the packet at the head of `buf`, or null when more bytes are needed to tell.
/// Zero means the opcode is unknown to this build and the stream cannot be resynchronised.
pub fn packetSize(v: Version, buf: []const u8) ?usize {
    return sc_versions.packetSize(v, buf);
}

test "the builds this client can frame, and the ones it refuses to guess at" {
    try std.testing.expectEqual(@as(?Version, .v106b), fromEngine("1.06b"));
    try std.testing.expectEqual(@as(?Version, .v107), fromEngine("1.07"));
    try std.testing.expectEqual(@as(?Version, .v110f), fromEngine("1.10f"));
    try std.testing.expectEqual(@as(?Version, .v114d), fromEngine("1.14d"));
    try std.testing.expectEqual(@as(?Version, .v108), fromEngine("1.08"));
    try std.testing.expectEqual(@as(?Version, .v109b), fromEngine("1.09b"));
    try std.testing.expectEqual(@as(?Version, .v113c), fromEngine("1.13c"));
    // Still refused rather than guessed at: no D2Net for these has been read.
    try std.testing.expectEqual(@as(?Version, null), fromEngine("1.00"));
    try std.testing.expectEqual(@as(?Version, null), fromEngine("1.11b"));
}

test "GameFlags is framed by the build, and the LoadSuccess behind it survives" {
    // The exact wire shape that hung 1.06b, now for every era: GameFlags and LoadSuccess in one
    // read. One byte too long and the handshake is eaten.
    for ([_]struct { v: Version, n: usize }{
        .{ .v = .v106b, .n = 6 },
        .{ .v = .v107, .n = 7 },
        .{ .v = .v110f, .n = 8 },
        .{ .v = .v114d, .n = 8 },
    }) |c| {
        var wire = [_]u8{ 0x01, 1, 2, 3, 4, 5, 6, 7, 0 };
        wire[c.n] = 0x02;
        try std.testing.expectEqual(@as(?usize, c.n), packetSize(c.v, wire[0 .. c.n + 1]));
        try std.testing.expectEqual(@as(u8, 0x02), wire[c.n]);
    }
}

test "a partial GameFlags asks for more bytes rather than guessing" {
    try std.testing.expectEqual(@as(?usize, null), packetSize(.v110f, &[_]u8{ 0x01, 1, 2, 3, 4, 5 }));
    try std.testing.expectEqual(@as(?usize, null), packetSize(.v106b, &[_]u8{}));
}
