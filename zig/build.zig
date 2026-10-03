const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const server_exe = b.addExecutable(.{
        .name = "mesh-server",
        .root_source_file = b.path("src/server/server_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(server_exe);

    const client_exe = b.addExecutable(.{
        .name = "mesh-client",
        .root_source_file = b.path("src/client/client_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(client_exe);

    const android_lib = b.addSharedLibrary(.{
        .name = "core",
        .root_source_file = b.path("src/android_jni/jni_bridge.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(android_lib);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("tests/test_frame.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
