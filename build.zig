const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;

// TODO use wine

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    if (builtin.os.tag == .wasi) return;
    const test_step = b.step("test", "Run unit tests");

    const main_cpp = b.addExecutable(.{
        .name = "main_win32acl",
        .optimize = optimize,
        .target = target,
    });
    main_cpp.addCSourceFile(.{
        .file = .{ .path = "win32acl.cpp" },
        .flags =  &[0][]const u8{}
    });
    main_cpp.linkLibCpp();
    b.installArtifact(main_cpp);

    const run_win32acl_cpp_test = b.addRunArtifact(main_cpp);
    // run_win32acl_cpp_test.step.dependOn(b.getInstallStep());
    run_win32acl_cpp_test.addFileArg( .{ .path = "./LICENSE" } );

    run_win32acl_cpp_test.step.dependOn(b.getInstallStep());
    run_win32acl_cpp_test.expectExitCode(0);

    if (b.host.result.os.tag == .windows) {
        const run_win32acl_cpp = b.step("runacl", "Run C++ win32kacl.");
        run_win32acl_cpp.dependOn(&run_win32acl_cpp_test.step);
        test_step.dependOn(&run_win32acl_cpp_test.step);
    }
}
