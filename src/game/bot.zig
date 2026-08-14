//! A self-contained "Mephisto run" bot for the pure-Zig d2gs-standalone host: enter a game,
//! traverse the inter-level warp graph toward Durance of Hate Level 3 (area 102), find the
//! boss/unique monster there, and attack it until it dies — no real D2 engine anywhere.
//!
//! This module owns the bot LOGIC only. It reads the S->C world model (world.zig) and emits
//! C->S game commands through a caller-supplied `send` callback; main.zig owns the socket, the
//! GAMELOGON/ENTERGAME handshake, and the S->C framing that feeds `world.apply`.
//!
//! C->S command layouts are byte-exact with what the standalone actually parses in
//! game_instance.zig `handleCommand` (which decodes the libd2 `cs` structs in
//! packages/sim/src/net/cs.zig):
//!   run-to-location   0x03 [op u8][x u16][y u16]                    (5)  -> cs.RunToLocation
//!   walk-to-location  0x01 [op u8][x u16][y u16]                    (5)  -> cs.WalkToLocation
//!   right-skill-loc   0x0C [op u8][x u16][y u16]                    (5)  -> cs.RightSkillOnLocation (Teleport)
//!   interact-entity   0x13 [op u8][unitType u32][guid u32]          (9)  -> cs.InteractWithEntity
//!   left-skill-entity 0x06 [op u8][unitType u32][guid u32]          (9)  -> cs.LeftSkillOnEntity ("attack")
//! All multi-byte integers are little-endian (x86). "Attack" is not a distinct opcode: it is a
//! left-skill cast against a unit (the standalone's castSkill path with the target's guid).
//!
//! MOVEMENT is TELEPORT, not running: the sorc's right hand is armed with Teleport (Skills.txt Id
//! 54) by the standalone at spawn, so a 0x0C right-skill-on-location cast repositions the player
//! instantly to (x,y) if that cell is passable + in range (~40 subtiles) + mana suffices — jumping
//! over the Durance swarm instead of grinding through it on foot. We aim each hop a bounded step
//! toward the target so the destination stays inside teleport range and the server accepts it.

const std = @import("std");
const builtin = @import("builtin");
const world_mod = @import("libd2").client;
const clt = @import("libd2").net.clt;
const World = world_mod.World;
const UnitType = world_mod.UnitType;

/// Always-on run log, but silent under the test runner: with `--listen=-` the build runner OWNS
/// stdout as its IPC channel, so a stray print there fails the whole test command. Same guard as
/// world.zig's `note`.
fn note(comptime fmt: []const u8, args: anytype) void {
    if (builtin.is_test) return;
    std.debug.print(fmt, args);
}

pub const DURANCE_L3: u16 = 102; // eLevelId DuranceofHateLvl3 — the run's target area
pub const MEPHISTO_CLASS: u16 = 242; // Mephisto's MonStats.txt id (hcIdx 242) — the boss we hunt


/// Max teleport hop toward a far target (world subtiles). The server caps a teleport to ~40
/// subtiles (TELEPORT_RANGE); we aim a hop of 32 so the destination is comfortably in range and
/// the cast is accepted, then re-cast next tick from the new position until we close on the goal.
const TELEPORT_HOP: i32 = 32;

/// Clamp (px,py)->(tx,ty) to a hop of at most TELEPORT_HOP subtiles so the destination stays inside
/// the server's teleport range. Returns the clamped (hx,hy) cell to cast Teleport at. Pure.
fn teleportHop(px: i32, py: i32, tx: i32, ty: i32) struct { x: u16, y: u16 } {
    var dx = tx - px;
    var dy = ty - py;
    const dist2: i64 = @as(i64, dx) * dx + @as(i64, dy) * dy;
    if (dist2 > @as(i64, TELEPORT_HOP) * TELEPORT_HOP) {
        const denom: i32 = @max(@as(i32, @intCast(@abs(dx))), @as(i32, @intCast(@abs(dy))));
        dx = @divTrunc(dx * TELEPORT_HOP, denom);
        dy = @divTrunc(dy * TELEPORT_HOP, denom);
    }
    return .{ .x = @intCast(@max(0, px + dx)), .y = @intCast(@max(0, py + dy)) };
}



pub const Phase = enum { pathing, fighting, done };

/// The run driver: a small state machine ticked once per S->C read pass. It never blocks — each
/// `step` inspects the current world and, if warranted, emits ONE C->S command via `sendFn`.
/// `ctx`/`sendFn` are the caller's socket writer.
pub const Driver = struct {
    ctx: *anyopaque,
    sendFn: *const fn (ctx: *anyopaque, bytes: []const u8) void,

    phase: Phase = .pathing,
    cur_level: u16 = 0, // last LoadAct level we announced
    target_warp: u32 = 0, // guid of the warp we're currently walking to (0 = none picked)
    target_monster: u32 = 0, // guid of the monster we're currently attacking (0 = none picked)
    attacks_sent: u32 = 0,
    used_warps: [16]u32 = [_]u32{0} ** 16, // warp GUIDs we've already interacted (loop guard)
    used_n: usize = 0,
    fight_ticks: u32 = 0, // ticks spent on the target level (grace for the monster burst)
    saw_monster: bool = false, // have we ever seen a monster on the target level?

    fn send(self: *Driver, bytes: []const u8) void {
        self.sendFn(self.ctx, bytes);
    }

    /// Teleport one hop toward (tx,ty) from (px,py): cast the right-hand skill (Teleport) at the
    /// range-clamped destination via 0x0C. This is the bot's ONLY locomotion — it never runs.
    fn teleportToward(self: *Driver, px: i32, py: i32, tx: i32, ty: i32) void {
        const hop = teleportHop(px, py, tx, ty);
        var b: [clt.RightSkillOnLocation.SIZE]u8 = undefined;
        self.send(clt.RightSkillOnLocation.encode(.{ .x = hop.x, .y = hop.y }, &b));
    }

    fn warpUsed(self: *const Driver, guid: u32) bool {
        for (self.used_warps[0..self.used_n]) |g| if (g == guid) return true;
        return false;
    }

    fn markWarpUsed(self: *Driver, guid: u32) void {
        if (self.warpUsed(guid)) return;
        self.used_warps[self.used_n % self.used_warps.len] = guid;
        self.used_n += 1;
    }

    /// Pick an outgoing warp to head for. The destination level isn't on the wire (the standalone
    /// streams warps as AssignLevelWarp objects carrying only a warp-type graphic), so we pick the
    /// unused warp with the HIGHEST warp-type id: on the Durance chain the deeper/forward door
    /// (type 67) sorts above the return door (type 65), so this climbs 100->101->102 toward the
    /// boss. If we ever backtrack onto an already-visited level, the forward door there is still
    /// unused for that fresh level, so we re-climb. Returns the warp unit, or null if none remain.
    fn pickWarp(self: *const Driver, world: *const World) ?world_mod.Unit {
        var warps: [32]world_mod.Unit = undefined;
        const n = world.collectWarps(&warps);
        var best: ?world_mod.Unit = null;
        for (warps[0..n]) |w| {
            if (self.warpUsed(w.guid)) continue;
            if (best == null or w.class_id > best.?.class_id) best = w;
        }
        return best;
    }

    /// One driver tick. Call after each batch of S->C packets has been applied to `world`.
    /// Emits at most one movement/interact/attack command. Returns the current phase.
    pub fn step(self: *Driver, world: *World) Phase {
        // Announce level transitions (LoadAct updates world.level_id).
        if (world.level_id != self.cur_level) {
            self.cur_level = world.level_id;
            self.target_warp = 0;
            self.target_monster = 0;
            note("[meph] entered level {d} (monsters={d}, warps seen)\n", .{ self.cur_level, world.monsterCount() });
            if (self.cur_level == DURANCE_L3) {
                self.phase = .fighting;
                note("[meph] reached Durance of Hate Level 3 — hunting Mephisto\n", .{});
            }
        }

        return switch (self.phase) {
            .pathing => self.stepPathing(world),
            .fighting => self.stepFighting(world),
            .done => .done,
        };
    }

    fn stepPathing(self: *Driver, world: *World) Phase {
        const p = world.playerPos() orelse return .pathing;

        // Fight through anything blocking the way: if a monster is right next to us, hit it so the
        // swarm in the monster-heavy interior levels doesn't grind the bot down before it reaches
        // the next warp. (A left-skill cast against the unit — the same "attack" the fight uses.)
        if (world.nearestMonster()) |m| {
            const mdx: i64 = @as(i64, m.x) - @as(i64, p.x);
            const mdy: i64 = @as(i64, m.y) - @as(i64, p.y);
            if (mdx * mdx + mdy * mdy <= 16) {
                var ab: [clt.LeftSkillOnEntity.SIZE]u8 = undefined;
                self.send(clt.LeftSkillOnEntity.encode(.{ .unit_type = @intFromEnum(UnitType.monster), .unit_guid = m.guid }, &ab));
                return .pathing;
            }
        }

        // Already have a warp we're walking to? If we've closed on it, interact; else keep running.
        if (self.target_warp != 0) {
            if (world.getWarp(self.target_warp)) |w| {
                const dx: i64 = @as(i64, w.x) - @as(i64, p.x);
                const dy: i64 = @as(i64, w.y) - @as(i64, p.y);
                if (dx * dx + dy * dy <= 25) { // within ~5 subtiles — interact to transition
                    // Warps ride the wire as "object" units (game_instance.zig AssignLevelWarp),
                    // and the server matches its warp list by GUID, so interact as an object.
                    var b: [clt.LeftSkillOnEntity.SIZE]u8 = undefined;
                    self.send(clt.InteractWithEntity.encode(.{ .unit_type = @intFromEnum(UnitType.object), .guid = self.target_warp }, &b));
                    note("[meph] interacting warp guid=0x{x} -> transitioning\n", .{self.target_warp});
                    self.markWarpUsed(self.target_warp);
                    self.target_warp = 0;
                } else {
                    self.teleportToward(p.x, p.y, w.x, w.y); // teleport-hop toward the warp
                }
                return .pathing;
            }
            self.target_warp = 0; // warp vanished (we transitioned) — repick next tick
        }

        // Pick a warp toward the boss and start teleporting to it.
        if (self.pickWarp(world)) |w| {
            self.target_warp = w.guid;
            note("[meph] found warp guid=0x{x} type={d} at ({d},{d}) — heading there\n", .{ w.guid, w.class_id, w.x, w.y });
            self.teleportToward(p.x, p.y, w.x, w.y);
        }
        return .pathing;
    }

    fn stepFighting(self: *Driver, world: *World) Phase {
        // Kill-confirm: if the monster we were attacking got removed (0x0A), it's dead.
        if (self.target_monster != 0) {
            if (world.last_removed_monster == self.target_monster or world.getUnit(.monster, self.target_monster) == null) {
                note("[meph] MEPHISTO DEAD (guid=0x{x}, {d} attacks)\n", .{ self.target_monster, self.attacks_sent });
                self.phase = .done;
                return .done;
            }
        }

        // Wait for the world burst (LoadAct + monster stream) before deciding the level is empty:
        // the fight phase can begin the same tick we enter, before any 0xAC has arrived.
        self.fight_ticks += 1;
        if (world.monsterCount() > 0) self.saw_monster = true;


        // Target MEPHISTO SPECIFICALLY by his MonStats class id — not the nearest mob. If we
        // once locked onto him (target_monster set) and he's now gone, that's the real kill.
        const mon = world.monsterByClass(MEPHISTO_CLASS) orelse {
            if (self.target_monster != 0) {
                note("[meph] MEPHISTO DEAD (class {d} guid=0x{x}, {d} attacks)\n", .{ MEPHISTO_CLASS, self.target_monster, self.attacks_sent });
                self.phase = .done;
                return .done;
            }
            // Not locked on yet — keep waiting for the world burst to stream Mephisto (0xAC).
            if (self.fight_ticks > 200) {
                note("[meph] Mephisto (class {d}) never appeared on Durance 3 — aborting\n", .{MEPHISTO_CLASS});
                self.phase = .done;
                return .done;
            }
            return .fighting;
        };

        const p = world.playerPos() orelse return .fighting;
        const dx: i64 = @as(i64, mon.x) - @as(i64, p.x);
        const dy: i64 = @as(i64, mon.y) - @as(i64, p.y);

        if (self.target_monster != mon.guid) {
            self.target_monster = mon.guid;
            self.attacks_sent = 0;
            note("[meph] found Mephisto (monstat={d} guid=0x{x} hp={d}/128) at ({d},{d})\n", .{ mon.class_id, mon.guid, mon.life, mon.x, mon.y });
        }

        // Ice Bolt is a RANGED spell: blast from a stand-off distance rather than hugging Mephisto
        // (point-blank = tanking his hits). Teleport toward him only until inside Ice Bolt reach,
        // then hold and cast from range. dist^2 in subtiles.
        const d2 = dx * dx + dy * dy;
        const CAST_MAX: i64 = 24 * 24; // Ice Bolt reach — cast from here, don't close into melee
        if (d2 > CAST_MAX) { // out of cast range — teleport toward the boss
            self.teleportToward(p.x, p.y, mon.x, mon.y);
            return .fighting;
        }

        // In Ice Bolt range: spam LeftSkillOnEntity (Ice Bolt) at the boss.
        var b: [clt.LeftSkillOnEntity.SIZE]u8 = undefined;
        self.send(clt.LeftSkillOnEntity.encode(.{ .unit_type = @intFromEnum(UnitType.monster), .unit_guid = mon.guid }, &b));
        self.attacks_sent += 1;
        if (self.attacks_sent % 8 == 0)
            note("[meph] attacking Mephisto guid=0x{x} hp={d}/128 ({d} hits)\n", .{ mon.guid, mon.life, self.attacks_sent });
        return .fighting;
    }
};

test "teleportHop clamps a far target to a bounded hop toward it" {
    // Straight-line hop from (100,100) toward a far (900,100): clamped to +TELEPORT_HOP on x.
    const h = teleportHop(100, 100, 900, 100);
    try std.testing.expectEqual(@as(u16, @intCast(100 + TELEPORT_HOP)), h.x);
    try std.testing.expectEqual(@as(u16, 100), h.y);
    // A near target (within a hop) is reached exactly, no clamp.
    const near = teleportHop(100, 100, 110, 108);
    try std.testing.expectEqual(@as(u16, 110), near.x);
    try std.testing.expectEqual(@as(u16, 108), near.y);
}

test "driver emits a Teleport (0x0C right-skill-on-location) cast toward a warp, never a run" {
    const gpa = std.testing.allocator;
    var world = World.init(gpa);
    defer world.deinit();

    // A local player at (100,100).
    var mk = [_]u8{0} ** 26;
    mk[0] = 0x59; // CreatePlayer
    std.mem.writeInt(u32, mk[1..5], 0x1000, .little);
    std.mem.writeInt(u16, mk[22..24], 100, .little);
    std.mem.writeInt(u16, mk[24..26], 100, .little);
    world.apply(&mk);

    // A far warp at (900,100) — the driver must teleport-hop toward it, not run.
    // Layout: [0x09][type u8][guid u32][classId u8][x u16][y u16] (11).
    var wp = [_]u8{0} ** 11;
    wp[0] = 0x09; // AssignLevelWarp
    wp[1] = 0x02; // wire unit_type "object"
    std.mem.writeInt(u32, wp[2..6], 0x44332211, .little);
    wp[6] = 67; // warp-type graphic
    std.mem.writeInt(u16, wp[7..9], 900, .little);
    std.mem.writeInt(u16, wp[9..11], 100, .little);
    world.apply(&wp);

    // Capture what the driver sends.
    const Cap = struct {
        buf: [64]u8 = undefined,
        len: usize = 0,
        fn sink(ctx: *anyopaque, bytes: []const u8) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const n = @min(bytes.len, self.buf.len);
            @memcpy(self.buf[0..n], bytes[0..n]);
            self.len = n;
        }
    };
    var cap = Cap{};
    var drv = Driver{ .ctx = &cap, .sendFn = &Cap.sink };

    _ = drv.step(&world);
    try std.testing.expect(cap.len == 5); // a location command
    try std.testing.expectEqual(clt.RightSkillOnLocation.OPCODE, cap.buf[0]); // Teleport cast, not clt.RunToLocation.OPCODE
    // The cast target is a bounded hop toward the warp (x clamped to 100+TELEPORT_HOP, not 900).
    const cx = std.mem.readInt(u16, cap.buf[1..3], .little);
    try std.testing.expectEqual(@as(u16, @intCast(100 + TELEPORT_HOP)), cx);
}

test "libd2's RunToLocation is byte-exact, LE" {
    // These bytes were verified against a live server back when this file encoded them itself.
    // Pointing the same expectation at libd2's generated encoder makes them a check on it.
    var b: [clt.RunToLocation.SIZE]u8 = undefined;
    const w = clt.RunToLocation.encode(.{ .x = 5000, .y = 6001 }, &b);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x88, 0x13, 0x71, 0x17 }, w);
}

test "libd2's on-entity commands are byte-exact (unitType u32, guid u32, LE)" {
    var b: [clt.LeftSkillOnEntity.SIZE]u8 = undefined;
    const atk = clt.LeftSkillOnEntity.encode(.{ .unit_type = 1, .unit_guid = 0x1234 }, &b);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x06, 1, 0, 0, 0, 0x34, 0x12, 0, 0 }, atk);
    const it = clt.InteractWithEntity.encode(.{ .unit_type = 5, .guid = 0xDEADBEEF }, &b);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x13, 5, 0, 0, 0, 0xEF, 0xBE, 0xAD, 0xDE }, it);
}
