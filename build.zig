const std = @import("std");

// Clientless Diablo II 1.14d Battle.net — a pure-Zig client that speaks the BNCS,
// MCP (realm/character), BNFTP, and D2GS game protocols with no game binary.
//
//   zig build                 build the single `clientless` binary into zig-out/bin/
//   zig build run -- <args>   run the BNCS/MCP/game client
//   zig build bnftp -- <args> run the BNFTP file client (== `clientless bnftp ...`)
//   zig build test            run the crypto unit tests (CheckRevision / CD-key / xSHA-1)
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const net = b.dependency("d2_net", .{ .target = target, .optimize = optimize });
    const core = b.dependency("d2_core", .{ .target = target, .optimize = optimize });
    const util = b.dependency("d2_util", .{ .target = target, .optimize = optimize });
    const client = b.dependency("d2_client", .{ .target = target, .optimize = optimize });
    const libd2 = [_]std.Build.Module.Import{
        .{ .name = "d2-net", .module = net.module("d2-net") },
        .{ .name = "d2-core", .module = core.module("d2-core") },
        .{ .name = "d2-util", .module = util.module("d2-util") },
        .{ .name = "d2-client", .module = client.module("d2-client") },
    };

    // ── d2-session: the socket, the stream and the world it describes. Public, because the
    //    scripting host needs exactly this and nothing above it — forking it would put a second
    //    copy of the framing rules somewhere they could drift. ──
    const sess = b.addModule("d2-session", .{
        .root_source_file = b.path("src/game/session.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &libd2,
    });

    // ── clientless: BNCS auth + CD-keys + OLS login + MCP realm/char + chat/ladder +
    //    D2GS game entry. Uses libc sockets (std.net is gone in 0.16). ──
    const exe = b.addExecutable(.{
        .name = "clientless",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &libd2,
        }),
    });
    exe.root_module.addImport("d2-session", sess);
    exe.root_module.addAnonymousImport("checkrev_core", .{ .root_source_file = b.path("src/checkrev_core.zig") });
    exe.root_module.addAnonymousImport("cdkey", .{ .root_source_file = b.path("src/cdkey.zig") });
    exe.root_module.addAnonymousImport("xsha1", .{ .root_source_file = b.path("src/xsha1.zig") });
    // BNFTP is folded into the one binary as the `bnftp` subcommand (it only needs std);
    // main.zig's dispatcher hands off to it.
    exe.root_module.addAnonymousImport("bnftp", .{ .root_source_file = b.path("src/bnftp.zig") });
    b.installArtifact(exe);

    // Expose the BNFTP fetch logic as a public module so downstream packages can
    // `@import("bnftp")` and call `bnftp.fetch(...)` (e.g. the re-fetch poller).
    _ = b.addModule("bnftp", .{ .root_source_file = b.path("src/bnftp.zig") });

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Run the clientless client (BNCS/MCP/game; `bnftp ...` subcommand for BNFTP)").dependOn(&run.step);

    // Convenience: `zig build bnftp -- <args>` == `clientless bnftp <args>`.
    const run_bnftp = b.addRunArtifact(exe);
    run_bnftp.step.dependOn(b.getInstallStep());
    run_bnftp.addArg("bnftp");
    if (b.args) |args| run_bnftp.addArgs(args);
    b.step("bnftp", "Run the BNFTP file client (clientless bnftp ...)").dependOn(&run_bnftp.step);

    // ── crypto unit tests: standard SHA-1 (CheckRevision), WC3 26-char CD-key decode,
    //    Blizzard broken SHA-1 (OLS password) — each module carries its own `test`s. ──
    const test_step = b.step("test", "Run the crypto unit tests");
    for ([_][]const u8{ "src/checkrev_core.zig", "src/cdkey.zig", "src/xsha1.zig", "src/game/bot.zig" }) |path| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
                .imports = &libd2,
            }),
        });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }
}
