const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const common_mod = b.createModule(.{
        .root_source_file = b.path("src/common/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const server_mod = b.createModule(.{
        .root_source_file = b.path("src/server/server_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_mod.addImport("common", common_mod);

    const server_exe = b.addExecutable(.{
        .name = "mesh-server",
        .root_module = server_mod,
    });
    b.installArtifact(server_exe);
    const server_step = b.step("server", "Build server executable");
    server_step.dependOn(&b.addInstallArtifact(server_exe, .{}).step);

    const client_mod = b.createModule(.{
        .root_source_file = b.path("src/client/client_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    client_mod.addImport("common", common_mod);

    const client_exe = b.addExecutable(.{
        .name = "mesh-client",
        .root_module = client_mod,
    });
    b.installArtifact(client_exe);
    const client_step = b.step("client", "Build client executable");
    client_step.dependOn(&b.addInstallArtifact(client_exe, .{}).step);

    const android_mod = b.createModule(.{
        .root_source_file = b.path("src/android_jni/jni_bridge.zig"),
        .target = target,
        .optimize = optimize,
    });
    android_mod.addImport("common", common_mod);

    const android_lib = b.addLibrary(.{
        .name = "core",
        .linkage = .dynamic,
        .root_module = android_mod,
    });
    b.installArtifact(android_lib);
    const android_step = b.step("android_lib", "Build android library");
    android_step.dependOn(&b.addInstallArtifact(android_lib, .{}).step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("tests/test_all.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("common", common_mod);

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
