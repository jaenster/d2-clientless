//! Client-side world model reconstructed from the D2GS server->client stream.
//!
//! The real client keeps units in `ServerSideUnitHashTables` keyed by (type, guid) and looks
//! them up with UNITS_FindClientSideUnit @0x00463990. We keep the same shape: a map keyed by
//! (unitType << 32 | guid). Packets mutate this model; nothing here talks to a renderer.
//!
//! Field offsets for each packet are taken from the 1.14d handlers (docs/re/sc-packets.md).
//! Handlers whose exact layout is still being recovered are logged but not yet applied.

const std = @import("std");
const builtin = @import("builtin");
const packets = @import("packets.zig");
const BitReader = @import("bitreader.zig").BitReader;
const item_mod = @import("item.zig");
pub const Item = item_mod.Item;

/// Always-on world log line, but silent under the test runner (its stdio is the IPC channel).
fn note(comptime fmt: []const u8, args: anytype) void {
    if (builtin.is_test) return;
    std.debug.print(fmt, args);
}

pub const UnitType = enum(u8) {
    player = 0,
    monster = 1,
    object = 2,
    missile = 3,
    item = 4,
    warp = 5,
    _,
};

pub const Unit = struct {
    utype: u8,
    guid: u32,
    x: u16 = 0,
    y: u16 = 0,
    life: u8 = 0, // 0..128 percent-ish, as the wire carries it
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,

    pub fn nameSlice(self: *const Unit) []const u8 {
        return self.name[0..self.name_len];
    }
};

fn unitKey(utype: u8, guid: u32) u64 {
    return (@as(u64, utype) << 32) | guid;
}

// A few common eD2UnitStat ids for readable stat logging (full set is in ItemStatCost).
fn statName(id: u16) []const u8 {
    return switch (id) {
        0 => "strength",
        1 => "energy",
        2 => "dexterity",
        3 => "vitality",
        7 => "maxhp",
        9 => "maxmana",
        11 => "maxstamina",
        12 => "level",
        13 => "experience",
        14 => "gold",
        15 => "goldbank",
        else => "stat",
    };
}

pub const World = struct {
    gpa: std.mem.Allocator,
    units: std.AutoHashMap(u64, Unit),
    ground_items: std.AutoHashMap(u32, Item), // fully-decoded items lying on the floor, by GUID
    player_stats: std.AutoHashMap(u16, i32), // local player stats by eD2UnitStat id (0x1d/1e/1f)

    // level / world identity (0x01 GameFlags, 0x03 LoadAct)
    difficulty: u8 = 0,
    expansion: bool = false,
    ladder: bool = false,
    act: u8 = 0,
    level_id: u16 = 0, // nArea from 0x03 LoadAct / eLevel from 0x07 MapReveal
    map_seed: u32 = 0, // DRLG seed for the current act (0x03 LoadAct)
    automap: u32 = 0, // 0x03 LoadAct nAutomap

    local_player_guid: ?u32 = null,
    local_hp: u16 = 0, // integer HP of the local player (0x18/0x95)
    local_mp: u16 = 0,
    local_stamina: u16 = 0,
    verbose: bool = false,

    pub fn init(gpa: std.mem.Allocator) World {
        return .{
            .gpa = gpa,
            .units = std.AutoHashMap(u64, Unit).init(gpa),
            .ground_items = std.AutoHashMap(u32, Item).init(gpa),
            .player_stats = std.AutoHashMap(u16, i32).init(gpa),
        };
    }

    pub fn deinit(self: *World) void {
        self.units.deinit();
        self.ground_items.deinit();
        self.player_stats.deinit();
    }

    fn upsert(self: *World, utype: u8, guid: u32) !*Unit {
        const gop = try self.units.getOrPut(unitKey(utype, guid));
        if (!gop.found_existing) gop.value_ptr.* = .{ .utype = utype, .guid = guid };
        return gop.value_ptr;
    }

    /// Feed one framed S->C packet (starting at the opcode byte). Compressed 0xAE containers
    /// must be decompressed and their inner packets fed here individually by the caller.
    pub fn apply(self: *World, buf: []const u8) void {
        if (buf.len == 0) return;
        const op = buf[0];
        const cat = packets.info(op).cat;
        switch (op) {
            0x01 => self.applyGameFlags(buf),
            0x03 => self.applyLoadAct(buf),
            0x07 => self.applyMapReveal(buf),
            0x09 => self.applyAssignWarp(buf),
            0x0a => self.applyRemove(buf),
            0x0f, 0x10 => self.applyPlayerMove(buf), // dest x@0xC y@0xE
            0x15 => self.applyReassign(buf),
            0x18 => self.applyLife(buf, true), // has hp/mp regen fields
            0x1d => self.applyStat(buf, 1), // [id][statId][value u8]
            0x1e => self.applyStat(buf, 2), // value u16
            0x1f => self.applyStat(buf, 4), // value u32
            0x95 => self.applyLife(buf, false),
            0x51 => self.applyCreateObject(buf),
            0x59 => self.applyCreatePlayer(buf),
            0x68 => self.applyMonsterMove(buf, 6, 8), // MonsterBeginCast x@6 y@8
            0x6b, 0x6c => self.applyMonsterMove(buf, 0x0c, 0x0e), // MonsterBeginCastWalk / CastStationary
            0xac => self.applyCreateMonster(buf),
            0x9c => self.applyItemAction(buf),
            else => self.logUnhandled(op, cat, buf),
        }
    }

    // 0x01 GameFlags: [id][difficulty u8][arenaFlags u32][expansion u8][ladder u8]
    fn applyGameFlags(self: *World, buf: []const u8) void {
        if (buf.len < 8) return;
        self.difficulty = buf[1];
        self.expansion = buf[6] != 0;
        self.ladder = buf[7] != 0;
        if (self.verbose)
            std.debug.print("  world: GameFlags diff={d} expansion={} ladder={}\n", .{ self.difficulty, self.expansion, self.ladder });
    }

    // 0x03 LoadAct @0045C8E0: [id][act u8][mapSeed u32@0x02][nArea u16@0x06][nAutomap u32@0x08].
    // CLIENT_AllocAct(nAct, nMapSeed, nAutomap, nArea). No object seed here (D2MOO diverges).
    fn applyLoadAct(self: *World, buf: []const u8) void {
        if (buf.len < 12) return;
        self.act = buf[1];
        self.map_seed = std.mem.readInt(u32, buf[2..6], .little);
        self.level_id = std.mem.readInt(u16, buf[6..8], .little);
        self.automap = std.mem.readInt(u32, buf[8..12], .little);
        note("  world: LoadAct act={d} area={d} mapSeed=0x{x:0>8}\n", .{ self.act, self.level_id, self.map_seed });
    }

    // 0x07 MapReveal @0045CAB0: [id][nX u16][nY u16][eLevel u8] -> AddRoomData(act, eLevel, x, y).
    fn applyMapReveal(self: *World, buf: []const u8) void {
        if (buf.len < 6) return;
        self.level_id = buf[5];
        if (self.verbose) {
            const x = std.mem.readInt(u16, buf[1..3], .little);
            const y = std.mem.readInt(u16, buf[3..5], .little);
            std.debug.print("  world: MapReveal level={d} at ({d},{d})\n", .{ self.level_id, x, y });
        }
    }

    // 0x09 AssignLevelWarp @0045CB90: [id][type u8][guid u32][classId u8][x u16][y u16].
    fn applyAssignWarp(self: *World, buf: []const u8) void {
        if (buf.len < 11) return;
        const u = self.upsert(buf[1], std.mem.readInt(u32, buf[2..6], .little)) catch return;
        u.x = std.mem.readInt(u16, buf[7..9], .little);
        u.y = std.mem.readInt(u16, buf[9..11], .little);
    }

    // 0x15 ReassignPlayer @0045D160: [id][type u8][guid u32][x u16@0x06][y u16@0x08][moveFlag u8].
    fn applyReassign(self: *World, buf: []const u8) void {
        if (buf.len < 11) return;
        const u = self.upsert(buf[1], std.mem.readInt(u32, buf[2..6], .little)) catch return;
        u.x = std.mem.readInt(u16, buf[6..8], .little);
        u.y = std.mem.readInt(u16, buf[8..10], .little);
        if (self.verbose)
            std.debug.print("  world: reassign type={d} guid=0x{x} -> ({d},{d})\n", .{ u.utype, u.guid, u.x, u.y });
    }

    // 0x51 CreateObject @0045CBD0: [id][type u8][guid u32][classId u16@0x06][x u16@0x08][y u16@0x0A][state u8][interaction u8].
    fn applyCreateObject(self: *World, buf: []const u8) void {
        if (buf.len < 14) return;
        const u = self.upsert(buf[1], std.mem.readInt(u32, buf[2..6], .little)) catch return;
        u.x = std.mem.readInt(u16, buf[8..10], .little);
        u.y = std.mem.readInt(u16, buf[10..12], .little);
    }

    // 0x59 UNIT_CreatePlayer @0045E4C0: [id][guid u32@0x01][classId u8@0x05][name[16]@0x06][x u16@0x16][y u16@0x18].
    fn applyCreatePlayer(self: *World, buf: []const u8) void {
        if (buf.len < 26) return;
        const guid = std.mem.readInt(u32, buf[1..5], .little);
        const u = self.upsert(@intFromEnum(UnitType.player), guid) catch return;
        const raw = buf[6..22];
        var nlen: u8 = 0;
        while (nlen < 16 and raw[nlen] != 0) nlen += 1;
        @memcpy(u.name[0..16], raw);
        u.name_len = nlen;
        u.x = std.mem.readInt(u16, buf[22..24], .little);
        u.y = std.mem.readInt(u16, buf[24..26], .little);
        if (self.local_player_guid == null) self.local_player_guid = guid; // first player seen = us
        note("  world: CreatePlayer \"{s}\" guid=0x{x} at ({d},{d})\n", .{ u.nameSlice(), guid, u.x, u.y });
    }

    // 0x18 Life @0045D9B0 / 0x95 PlayerJoin @0045DB20: bit-packed (Fog::BitBuffer, LSB-first).
    // hp/mp/stamina u15 each (engine keeps them <<8 as 1/256 fixed-point), then (0x18 only) two
    // u7 regen fields, then absolute tile x/y u16 + signed u8 dx/dy deltas. Local player only —
    // no guid on the wire. Field order/widths per RE (docs/re/sc-packets.md); bit direction is
    // LSB-first per D2 convention (bitreader.zig verified), packet field widths not yet capture-verified.
    fn applyLife(self: *World, buf: []const u8, has_regen: bool) void {
        const min: usize = if (has_regen) 15 else 13;
        if (buf.len < min) return;
        var r = BitReader.init(buf);
        _ = r.read(8); // opcode byte
        self.local_hp = @intCast(r.read(15));
        self.local_mp = @intCast(r.read(15));
        self.local_stamina = @intCast(r.read(15));
        if (has_regen) {
            _ = r.read(7); // hp regen
            _ = r.read(7); // mp regen
        }
        const x: u16 = @intCast(r.read(16));
        const y: u16 = @intCast(r.read(16));
        if (self.local_player_guid) |g| {
            if (self.units.getPtr(unitKey(@intFromEnum(UnitType.player), g))) |u| {
                u.x = x;
                u.y = y;
            }
        }
        note("  world: life hp={d} mp={d} stam={d} at ({d},{d})\n", .{ self.local_hp, self.local_mp, self.local_stamina, x, y });
    }

    // 0x1D/0x1E/0x1F stat update (shared handler @0045D780): [id][statId u8][value] where the
    // value width (1/2/4 bytes) is chosen by the opcode. Sets a local-player stat by eD2UnitStat
    // id. hp/mana/stamina are stored ×256 (fixed point) — see statName/dumpSummary.
    fn applyStat(self: *World, buf: []const u8, width: usize) void {
        if (buf.len < 2 + width) return;
        const stat_id: u16 = buf[1];
        const value: i32 = switch (width) {
            1 => buf[2],
            2 => std.mem.readInt(u16, buf[2..4], .little),
            4 => @bitCast(std.mem.readInt(u32, buf[2..6], .little)),
            else => return,
        };
        self.player_stats.put(stat_id, value) catch {};
        if (self.verbose)
            std.debug.print("  world: stat {s}(#{d}) = {d}\n", .{ statName(stat_id), stat_id, value });
    }

    // 0x0A RemoveObject @0045CC10: [id][unitType u8][guid u32].
    fn applyRemove(self: *World, buf: []const u8) void {
        if (buf.len < 6) return;
        const utype = buf[1];
        const guid = std.mem.readInt(u32, buf[2..6], .little);
        _ = self.units.remove(unitKey(utype, guid));
        if (self.verbose)
            std.debug.print("  world: remove type={d} guid=0x{x}\n", .{ utype, guid });
    }

    // 0x0F PlayerMove / 0x10 CharacterToObject @0045CD40/90: fpU (unit pre-resolved by the
    // dispatcher from type@0x01 guid@0x02); destination is a raw u16 x@0x0C y@0x0E. The moving
    // unit is a player. Guid offset follows the type@1/guid@2 convention (unconfirmed in-handler).
    fn applyPlayerMove(self: *World, buf: []const u8) void {
        if (buf.len < 16) return;
        const u = self.upsert(buf[1], std.mem.readInt(u32, buf[2..6], .little)) catch return;
        u.x = std.mem.readInt(u16, buf[0x0c..0x0e], .little);
        u.y = std.mem.readInt(u16, buf[0x0e..0x10], .little);
    }

    // 0x68/0x6B/0x6C monster movement (fpU): monster convention has guid@0x01 and NO type byte
    // (like 0xAC). Destination x/y offsets differ per opcode, passed in by the caller.
    fn applyMonsterMove(self: *World, buf: []const u8, xoff: usize, yoff: usize) void {
        if (buf.len < yoff + 2) return;
        const u = self.upsert(@intFromEnum(UnitType.monster), std.mem.readInt(u32, buf[1..5], .little)) catch return;
        u.x = std.mem.readInt(u16, buf[xoff..][0..2], .little);
        u.y = std.mem.readInt(u16, buf[yoff..][0..2], .little);
    }

    // 0xAC create/assign monster @0045F190: byte-aligned header [id][guid u32@1][monstat i16@5]
    // [x u16@7][y u16@9][hpPct u8@0xB][pktLen u8@0xC]; the trailing statlist (from +0xD) is a
    // bitstream we don't parse yet. Header alone gives the monster's identity + spawn position.
    fn applyCreateMonster(self: *World, buf: []const u8) void {
        if (buf.len < 13) return;
        const guid = std.mem.readInt(u32, buf[1..5], .little);
        const u = self.upsert(@intFromEnum(UnitType.monster), guid) catch return;
        u.x = std.mem.readInt(u16, buf[7..9], .little);
        u.y = std.mem.readInt(u16, buf[9..11], .little);
        u.life = buf[0x0b];
        if (self.verbose) {
            const monstat = std.mem.readInt(i16, buf[5..7], .little);
            std.debug.print("  world: CreateMonster monstat={d} guid=0x{x} at ({d},{d})\n", .{ monstat, guid, u.x, u.y });
        }
    }

    // 0x9C item action @0045EB10: [id][action u8][pktLen u8][reserved u8][itemGUID u32@0x04]
    // [item bitstream @0x08, len pktLen-8]. The bitstream fully describes the item (item.zig).
    // Ground-appear actions parse + store the item and place its unit; pickup removes it.
    fn applyItemAction(self: *World, buf: []const u8) void {
        if (buf.len < 8) return;
        const action = buf[1];
        const guid = std.mem.readInt(u32, buf[4..8], .little);
        switch (action) {
            0x00, 0x02, 0x03 => { // add / dropped / on-ground => item appears on the floor
                var r = BitReader.init(buf[8..]);
                const it = item_mod.parse(&r);
                self.ground_items.put(guid, it) catch {};
                if (it.on_ground) {
                    const u = self.upsert(@intFromEnum(UnitType.item), guid) catch return;
                    u.x = it.x;
                    u.y = it.y;
                }
                note("  world: item \"{s}\" {s}{s} guid=0x{x} at ({d},{d}) stats={d}\n", .{
                    it.codeSlice(), @tagName(it.quality), if (it.ethereal()) " eth" else "",
                    guid, it.x, it.y, it.n_stats,
                });
            },
            0x01 => { // picked from ground => gone from the world
                _ = self.units.remove(unitKey(@intFromEnum(UnitType.item), guid));
                _ = self.ground_items.remove(guid);
            },
            else => {}, // inventory/belt/shop/cursor moves: not floor presence, ignore for now
        }
    }

    fn logUnhandled(self: *World, op: u8, cat: packets.Cat, buf: []const u8) void {
        if (!self.verbose) return;
        var nb: [8]u8 = undefined;
        std.debug.print("  world: [{s}] {s} ({d} bytes) — decode pending\n", .{ @tagName(cat), packets.label(op, &nb), buf.len });
    }

    pub fn unitCount(self: *const World) u32 {
        return self.units.count();
    }

    /// Print a human-readable snapshot: level/seed, unit tallies, local player, ground items.
    pub fn dumpSummary(self: *const World) void {
        std.debug.print(
            "\n=== world ===\nact={d} level={d} mapSeed=0x{x:0>8} diff={d} exp={} ladder={}\n",
            .{ self.act, self.level_id, self.map_seed, self.difficulty, self.expansion, self.ladder },
        );
        if (self.local_player_guid) |g|
            std.debug.print("local player guid=0x{x} hp={d} mp={d} stam={d}\n", .{ g, self.local_hp, self.local_mp, self.local_stamina });
        if (self.player_stats.count() > 0) {
            std.debug.print("player stats:", .{});
            for ([_]u16{ 0, 1, 2, 3, 7, 9, 11, 12, 13, 14 }) |id| {
                if (self.player_stats.get(id)) |v| {
                    // hp/mana/stamina are ×256 fixed point
                    const shown = if (id == 7 or id == 9 or id == 11) @divTrunc(v, 256) else v;
                    std.debug.print(" {s}={d}", .{ statName(id), shown });
                }
            }
            std.debug.print("\n", .{});
        }
        var tally = [_]u32{0} ** 6;
        var it = self.units.valueIterator();
        while (it.next()) |u| {
            if (u.utype < tally.len) tally[u.utype] += 1;
        }
        std.debug.print("units: player={d} monster={d} object={d} missile={d} item={d} warp={d} (total {d})\n", .{ tally[0], tally[1], tally[2], tally[3], tally[4], tally[5], self.units.count() });
        std.debug.print("ground items: {d}\n", .{self.ground_items.count()});
        var gi = self.ground_items.iterator();
        while (gi.next()) |e| {
            const item = e.value_ptr;
            std.debug.print("  0x{x:0>8} \"{s}\" {s}{s} ilvl={d} sockets={d} at ({d},{d}) stats={d}\n", .{
                e.key_ptr.*,          item.codeSlice(),          @tagName(item.quality),
                if (item.ethereal()) " eth" else "", item.ilvl, item.sockets,
                item.x,               item.y,                    item.n_stats,
            });
        }
    }
};

test "LoadAct sets seed, act, area" {
    var w = World.init(std.testing.allocator);
    defer w.deinit();
    // act=1, mapSeed=0xDEADBEEF, area=0x0028, automap=0x11223344
    var p = [_]u8{ 0x03, 0x01, 0xEF, 0xBE, 0xAD, 0xDE, 0x28, 0x00, 0x44, 0x33, 0x22, 0x11 };
    w.apply(&p);
    try std.testing.expectEqual(@as(u8, 1), w.act);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), w.map_seed);
    try std.testing.expectEqual(@as(u16, 0x0028), w.level_id);
    try std.testing.expectEqual(@as(u32, 0x11223344), w.automap);
}

test "CreatePlayer then reassign tracks position" {
    var w = World.init(std.testing.allocator);
    defer w.deinit();
    var mk = [_]u8{0} ** 26;
    mk[0] = 0x59;
    std.mem.writeInt(u32, mk[1..5], 0x1000, .little);
    @memcpy(mk[6..10], "Bob\x00");
    std.mem.writeInt(u16, mk[22..24], 100, .little);
    std.mem.writeInt(u16, mk[24..26], 200, .little);
    w.apply(&mk);
    try std.testing.expectEqual(@as(u32, 1), w.unitCount());
    try std.testing.expectEqual(@as(?u32, 0x1000), w.local_player_guid);
    // reassign player (type 0) guid 0x1000 to (150,250)
    var rp = [_]u8{ 0x15, 0x00, 0x00, 0x10, 0x00, 0x00, 150, 0, 250, 0, 0 };
    w.apply(&rp);
    try std.testing.expectEqual(@as(u32, 1), w.unitCount()); // same unit, moved
    var it = w.units.valueIterator();
    const u = it.next().?;
    try std.testing.expectEqual(@as(u16, 150), u.x);
    try std.testing.expectEqual(@as(u16, 250), u.y);
}

test "Life (0x95) decodes hp/mp/stamina and repositions local player" {
    const BitWriter = @import("bitreader.zig").BitWriter;
    var w = World.init(std.testing.allocator);
    defer w.deinit();
    // make a local player first so 0x95 has a unit to reposition
    var mk = [_]u8{0} ** 26;
    mk[0] = 0x59;
    std.mem.writeInt(u32, mk[1..5], 0x2000, .little);
    std.mem.writeInt(u16, mk[22..24], 1, .little);
    std.mem.writeInt(u16, mk[24..26], 1, .little);
    w.apply(&mk);
    // build a 0x95: hp=100 mp=50 stam=80 x=5000 y=6000
    var buf = [_]u8{0} ** 13;
    var bw = BitWriter.init(&buf);
    bw.write(0x95, 8);
    bw.write(100, 15);
    bw.write(50, 15);
    bw.write(80, 15);
    bw.write(5000, 16);
    bw.write(6000, 16);
    w.apply(&buf);
    try std.testing.expectEqual(@as(u16, 100), w.local_hp);
    try std.testing.expectEqual(@as(u16, 50), w.local_mp);
    try std.testing.expectEqual(@as(u16, 80), w.local_stamina);
    const u = w.units.getPtr((@as(u64, 0) << 32) | 0x2000).?;
    try std.testing.expectEqual(@as(u16, 5000), u.x);
    try std.testing.expectEqual(@as(u16, 6000), u.y);
}

test "stat family decodes real Sorceress starting stats (from a live capture)" {
    var w = World.init(std.testing.allocator);
    defer w.deinit();
    w.apply(&[_]u8{ 0x1d, 0x00, 0x0a }); // strength = 10
    w.apply(&[_]u8{ 0x1d, 0x02, 0x19 }); // dexterity = 25
    w.apply(&[_]u8{ 0x1e, 0x07, 0x00, 0x28 }); // maxhp = 0x2800 (=40 after /256)
    w.apply(&[_]u8{ 0x1e, 0x0b, 0x00, 0x4a }); // maxstamina = 0x4a00 (=74)
    try std.testing.expectEqual(@as(i32, 10), w.player_stats.get(0).?);
    try std.testing.expectEqual(@as(i32, 25), w.player_stats.get(2).?);
    try std.testing.expectEqual(@as(i32, 0x2800), w.player_stats.get(7).?);
    try std.testing.expectEqual(@as(i32, 40), @divTrunc(w.player_stats.get(7).?, 256));
    try std.testing.expectEqual(@as(i32, 74), @divTrunc(w.player_stats.get(11).?, 256));
}

test "GameFlags + remove of an absent unit is harmless" {
    var w = World.init(std.testing.allocator);
    defer w.deinit();
    w.apply(&[_]u8{ 0x01, 0x02, 0, 0, 0, 0, 0x01, 0x01 });
    try std.testing.expectEqual(@as(u8, 2), w.difficulty);
    try std.testing.expect(w.expansion and w.ladder);
    w.apply(&[_]u8{ 0x0a, 0x01, 0x01, 0, 0, 0 });
    try std.testing.expectEqual(@as(u32, 0), w.unitCount());
}
