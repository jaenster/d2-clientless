//! D2GS server->client packet framing + opcode metadata (1.14d).
//!
//! The game stream is opcode-framed: `[opcode][payload...]`. Wire size per opcode is the
//! engine's NET_D2GS_CLIENT_INCOMING_SIZE table @0x730ae8 (0x00..0xB4); a few opcodes are
//! variable and size is derived from header fields, mirroring the engine's
//! GetIncomingPacketSizeFromTableAndVariableSize @0x0052b920.
//!
//! Names/categories come from the 1.14d handler table NET_D2GS_CLIENT_INCOMING @0x007114d0.
//! See docs/re/sc-packets.md.

const std = @import("std");

// NET_D2GS_CLIENT_INCOMING_SIZE @0x730ae8. >0 = fixed wire size; 0 = invalid/stub with no
// bytes; -1 = variable (derived in packetSize). Includes the opcode byte itself.
pub const SC_SIZE = [_]i16{
    1,  8,  1,  12, 1,  1,  1,  6,  6,  11, 6,  6,  9,  13, 12, 16, // 0x00
    16, 8,  26, 14, 18, 11, -1, 0,  15, 2,  2,  3,  5,  3,  4,  6, // 0x10
    10, 12, 12, 13, 90, 90, -1, 40, 103, 97, 15, 0,  8,  0,  0,  0, // 0x20
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  -1, 8, // 0x30
    13, 0,  6,  0,  0,  13, 0,  11, 11, 0,  0,  0,  16, 17, 7,  1, // 0x40
    15, 14, 42, 10, 3,  0,  0,  14, 7,  26, 40, -1, 5,  6,  38, 5, // 0x50
    7,  2,  7,  21, 0,  7,  7,  16, 21, 12, 12, 16, 16, 10, 1,  1, // 0x60
    1,  1,  1,  32, 10, 13, 6,  2,  21, 6,  13, 8,  6,  18, 5,  10, // 0x70
    0,  20, 29, 0,  0,  0,  0,  0,  0,  2,  6,  6,  11, 7,  10, 33, // 0x80
    13, 26, 6,  8,  -1, 13, 9,  1,  7,  16, 17, 7,  -1, -1, 7,  8, // 0x90
    10, 7,  8,  24, 3,  8,  -1, 7,  -1, 7,  -1, 7,  -1, 0,  -1, -1, // 0xA0
    1,  0,  53, -1, 5, // 0xB0..0xB4
};

pub const MAX_OPCODE = 0xB4;

/// Full wire size of the S->C packet at the front of `buf`, or null if the complete packet
/// isn't present yet (need more bytes). 0 = invalid opcode (desync). Mirrors the engine.
pub fn packetSize(buf: []const u8) ?usize {
    if (buf.len == 0) return null;
    const op = buf[0];
    if (op > MAX_OPCODE) return 0;
    const t = SC_SIZE[op];
    if (t == 0) return 0;
    if (t > 0) {
        const n: usize = @intCast(t);
        return if (buf.len >= n) n else null;
    }
    // variable-length: derive from header fields (engine GetIncomingPacketSize switch).
    const sz: ?usize = switch (op) {
        0x16, 0x5b => if (buf.len > 2) @as(usize, std.mem.readInt(u16, buf[1..3], .little)) else null,
        0x3e => if (buf.len > 1) @as(usize, buf[1]) else null,
        0x94 => if (buf.len > 1) (@as(usize, buf[1]) + 2) * 3 else null,
        0x9c, 0x9d => if (buf.len > 2) @as(usize, buf[2]) else null,
        0xa6 => if (buf.len > 3) @as(usize, std.mem.readInt(u16, buf[2..4], .little)) else null,
        0xa8, 0xaa => if (buf.len > 6) @as(usize, buf[6]) else null,
        0xac => if (buf.len > 0xc) @as(usize, buf[0xc]) else null,
        0xae => if (buf.len > 2) blk: {
            var raw = std.mem.readInt(u16, buf[1..3], .little);
            if (raw > 0x1fd) raw = 0;
            break :blk @as(usize, raw) + 3;
        } else null,
        0xaf => if (buf.len > 1) (if (buf[1] == 0) @as(usize, 2) else @as(usize, buf[1]) + 1) else null,
        0xb3 => if (buf.len > 7) @as(usize, buf[1]) + 7 else null,
        else => return 0,
    };
    const need = sz orelse return null;
    return if (buf.len >= need) need else null;
}

/// Coarse category used to route a packet into the world model and to decide how much to log.
pub const Cat = enum {
    control, // load/unload/handshake/game-flags: session lifecycle, no unit state
    level, // act/seed/map reveal: level & world identity
    unit_add, // a unit appears (player/object/item created)
    unit_remove, // a unit is removed
    move, // a unit changes position / walk / run / teleport
    life, // hp/mana/stamina
    stat, // stat set/add (str, exp, gold, resist, ...)
    state, // buff/debuff state add/remove/sync
    skill, // skill assign / cast / select
    item, // item ground/inventory/belt actions
    chat, // overhead text / messages
    roster, // party roster / quest / waypoint UI state
    misc, // named but not modelled
    unknown, // no dedicated handler (stub / bare-ret / unnamed)
};

const Info = struct { name: []const u8, cat: Cat };

/// Opcode metadata. Names are the 1.14d Ghidra handler symbol (short form). Opcodes with no
/// dedicated handler fall through to a generated "0xNN" name with cat=.unknown.
pub fn info(op: u8) Info {
    return switch (op) {
        0x00 => .{ .name = "Nop", .cat = .control },
        0x01 => .{ .name = "GameFlags", .cat = .control },
        0x02 => .{ .name = "LoadSuccess", .cat = .control },
        0x03 => .{ .name = "LoadAct", .cat = .level },
        0x04 => .{ .name = "LoadComplete", .cat = .control },
        0x05 => .{ .name = "UnloadComplete", .cat = .control },
        0x06 => .{ .name = "GameExit", .cat = .control },
        0x07 => .{ .name = "MapReveal", .cat = .level },
        0x08 => .{ .name = "MapHide", .cat = .level },
        0x09 => .{ .name = "AssignLevelWarp", .cat = .unit_add },
        0x0a => .{ .name = "RemoveObject", .cat = .unit_remove },
        0x0b => .{ .name = "HandShake", .cat = .control },
        0x0c => .{ .name = "NpcHit", .cat = .life },
        0x0d => .{ .name = "PlayerStop", .cat = .move },
        0x0e => .{ .name = "ObjectState", .cat = .state },
        0x0f => .{ .name = "PlayerMove", .cat = .move },
        0x10 => .{ .name = "CharacterToObject", .cat = .move },
        0x11 => .{ .name = "ReportKill", .cat = .misc },
        0x15 => .{ .name = "ReassignPlayer", .cat = .move },
        0x16 => .{ .name = "UnitUpdateBatch", .cat = .move },
        0x17 => .{ .name = "PlayerBeginCast", .cat = .skill },
        0x18 => .{ .name = "Life", .cat = .life },
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f => .{ .name = "ItemPageUpdate", .cat = .stat },
        0x20 => .{ .name = "Incoming0x20", .cat = .misc },
        0x21 => .{ .name = "Incoming0x21", .cat = .skill },
        0x22 => .{ .name = "SkillQuantity", .cat = .skill },
        0x23 => .{ .name = "SelectSkill", .cat = .skill },
        0x26 => .{ .name = "Incoming0x26", .cat = .chat },
        0x27 => .{ .name = "OverheadText", .cat = .chat },
        0x28 => .{ .name = "NpcInteract", .cat = .misc },
        0x29 => .{ .name = "Incoming0x29", .cat = .misc },
        0x2a => .{ .name = "Incoming0x2A", .cat = .misc },
        0x2c => .{ .name = "Incoming0x2C", .cat = .misc },
        0x47 => .{ .name = "RecalcEquippedItems", .cat = .misc },
        0x48 => .{ .name = "RecalcEquippedItems2", .cat = .misc },
        0x4c => .{ .name = "PlayerCast", .cat = .skill },
        0x4d => .{ .name = "PlayerCastTarget", .cat = .skill },
        0x51 => .{ .name = "CreateObject", .cat = .unit_add },
        0x53 => .{ .name = "Incoming0x53", .cat = .misc },
        0x59 => .{ .name = "CreatePlayer", .cat = .unit_add },
        0x5a => .{ .name = "Incoming0x5A", .cat = .misc },
        0x5b => .{ .name = "RosterPlayer", .cat = .roster },
        0x5d => .{ .name = "QuestState", .cat = .roster },
        0x67 => .{ .name = "MonsterStop", .cat = .move },
        0x68 => .{ .name = "MonsterBeginCast", .cat = .skill },
        0x69 => .{ .name = "MonsterSpell", .cat = .skill },
        0x6a => .{ .name = "NpcStateToEntity", .cat = .state },
        0x6b => .{ .name = "MonsterBeginCastWalk", .cat = .move },
        0x6c => .{ .name = "MonsterCastStationary", .cat = .skill },
        0x73 => .{ .name = "WaypointInit", .cat = .roster },
        0x77 => .{ .name = "TradeWindow", .cat = .item },
        0x7b => .{ .name = "SetSkillSlot", .cat = .skill },
        0x7c => .{ .name = "ItemAction", .cat = .item },
        0x8e => .{ .name = "RosterOtherAllocFree", .cat = .roster },
        0x93 => .{ .name = "SkillTabBonusDelta", .cat = .skill },
        0x95 => .{ .name = "PlayerJoin", .cat = .life },
        0x96 => .{ .name = "PlayerLeave", .cat = .unit_remove },
        0x98 => .{ .name = "Incoming0x98", .cat = .roster },
        0x9c => .{ .name = "Item", .cat = .item },
        0x9d => .{ .name = "Incoming0x9D", .cat = .item },
        0x9e, 0x9f, 0xa0, 0xa1, 0xa2 => .{ .name = "MonsterStat", .cat = .stat },
        0xa7 => .{ .name = "State", .cat = .state },
        0xa8 => .{ .name = "StateStatList", .cat = .state },
        0xa9 => .{ .name = "State2", .cat = .state },
        0xaa => .{ .name = "StateStat", .cat = .state },
        0xac => .{ .name = "AssignMonster", .cat = .unit_add },
        0xae => .{ .name = "Compressed", .cat = .control },
        else => .{ .name = "?", .cat = .unknown },
    };
}

/// Human label for logging: symbolic name when known, else "0xNN".
pub fn label(op: u8, buf: []u8) []const u8 {
    const i = info(op);
    if (i.cat != .unknown) return i.name;
    return std.fmt.bufPrint(buf, "0x{x:0>2}", .{op}) catch "?";
}

test "size table covers 0x00..0xB4" {
    try std.testing.expectEqual(@as(usize, MAX_OPCODE + 1), SC_SIZE.len);
}

test "fixed-size framing needs full packet" {
    // 0x03 LoadAct is 12 bytes.
    try std.testing.expectEqual(@as(?usize, null), packetSize(&[_]u8{ 0x03, 0, 0 }));
    var full = [_]u8{0} ** 12;
    full[0] = 0x03;
    try std.testing.expectEqual(@as(?usize, 12), packetSize(&full));
}

test "invalid opcode is desync, not null" {
    try std.testing.expectEqual(@as(?usize, 0), packetSize(&[_]u8{0xff}));
}
