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

    // The libc socket layer, shared by the session and the realm legs. It is a module rather than
    // a relative import because a file may belong to exactly one module, and both legs need it.
    const sockets = b.addModule("d2-net-socket", .{
        .root_source_file = b.path("src/game/net.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // One dependency on libd2, and one import from it: the library re-exports every layer off a
    // single `libd2` module, so this list does not have to be kept in step with the library's own
    // layering, and naming a layer costs nothing until it is used.
    const d2 = b.dependency("libd2", .{ .target = target, .optimize = optimize });
    const libd2 = [_]std.Build.Module.Import{
        .{ .name = "libd2", .module = d2.module("libd2") },
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
    sess.addImport("d2-net-socket", sockets);

    // ── d2-realm: BNCS auth -> realm logon -> MCP character -> a game to dial. Public for the
    //    same reason as d2-session: a bot that has to get itself into a game needs this leg, and
    //    a second copy of the MCP order (STARTUP -> CHARLIST2 -> CHARLOGON, no MOTD) is a bug
    //    waiting to be reintroduced. ──
    const realm = b.addModule("d2-realm", .{
        .root_source_file = b.path("src/game/realm.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &libd2,
    });
    realm.addImport("d2-net-socket", sockets);

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
    exe.root_module.addImport("d2-realm", realm);
    // BNFTP is folded into the one binary as the `bnftp` subcommand; the wire format itself
    // comes from libd2 (shared with the realm server that answers it), and what is here is the
    // socket work and the CLI.
    // main.zig's dispatcher hands off to it.
    const bnftp_mod = b.addModule("bnftp", .{
        .root_source_file = b.path("src/bnftp.zig"),
        .imports = &libd2,
    });
    exe.root_module.addImport("bnftp", bnftp_mod);
    b.installArtifact(exe);

    // Expose the BNFTP fetch logic as a public module so downstream packages can
    // `@import("bnftp")` and call `bnftp.fetch(...)` (e.g. the re-fetch poller).

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

    // The crypto vectors moved to libd2's d2-bnet with the code they verify; what is left to
    // test here is this repo's own logic.
    const test_step = b.step("test", "Run the unit tests");
    // Every file with tests has to be named HERE. A test in a file this list does not mention is
    // compiled by nothing and run by nothing — it looks like coverage and is not.
    for ([_][]const u8{ "src/game/bot.zig", "src/game/framing.zig" }) |path| {
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
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = realm })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = sess })).step);
}
