const std = @import("std");

// Clientless Diablo II 1.14d Battle.net — a pure-Zig client that speaks the BNCS,
// MCP (realm/character), BNFTP, and D2GS game protocols with no game binary.
//
//   zig build                 build both binaries into zig-out/bin/
//   zig build run -- <args>   run the BNCS/MCP/game client
//   zig build bnftp -- <args> run the BNFTP file client
//   zig build test            run the crypto unit tests (CheckRevision / CD-key / xSHA-1)
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ── clientless: BNCS auth + CD-keys + OLS login + MCP realm/char + chat/ladder +
    //    D2GS game entry. Uses libc sockets (std.net is gone in 0.16). ──
    const exe = b.addExecutable(.{
        .name = "clientless",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    exe.root_module.addAnonymousImport("checkrev_core", .{ .root_source_file = b.path("src/checkrev_core.zig") });
    exe.root_module.addAnonymousImport("cdkey", .{ .root_source_file = b.path("src/cdkey.zig") });
    exe.root_module.addAnonymousImport("xsha1", .{ .root_source_file = b.path("src/xsha1.zig") });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.step.dependOn(b.getInstallStep());
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Run the clientless BNCS/MCP/game client").dependOn(&run.step);

    // ── bnftp: clientless BNFTP discovery/download client (selector 0x02). ──
    const bnftp = b.addExecutable(.{
        .name = "bnftp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bnftp.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    b.installArtifact(bnftp);
    const run_bnftp = b.addRunArtifact(bnftp);
    run_bnftp.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_bnftp.addArgs(args);
    b.step("bnftp", "Run the clientless BNFTP file client").dependOn(&run_bnftp.step);

    // ── crypto unit tests: standard SHA-1 (CheckRevision), WC3 26-char CD-key decode,
    //    Blizzard broken SHA-1 (OLS password) — each module carries its own `test`s. ──
    const test_step = b.step("test", "Run the crypto unit tests");
    for ([_][]const u8{ "src/checkrev_core.zig", "src/cdkey.zig", "src/xsha1.zig" }) |path| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(path),
                .target = target,
                .optimize = optimize,
            }),
        });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }
}
