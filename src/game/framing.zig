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
/// 1.13c maps to 1.14d's table on evidence rather than adjacency: this client has decoded a full
/// world out of a 1.13c server with it — 179 packets and 53 units, with no resync. The builds that
/// return null are the ones where that has never been shown, and they are exactly the ones a
/// neighbour's table would silently hang.
pub fn fromEngine(name: []const u8) ?Version {
    const map = .{
        .{ "1.06b", Version.v106b },
        .{ "1.07", Version.v107 },
        .{ "1.10f", Version.v110f },
        .{ "1.13c", Version.v114d },
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
    // Never measured. Answering .v107 here would frame 1.08 with 1.07's table and hang if any
    // entry moved — the failure this whole file exists to stop.
    try std.testing.expectEqual(@as(?Version, null), fromEngine("1.08"));
    try std.testing.expectEqual(@as(?Version, null), fromEngine("1.09b"));
    try std.testing.expectEqual(@as(?Version, null), fromEngine("1.09d"));
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
