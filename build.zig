const std = @import("std");

pub fn build(b: *std.Build) void {
    const targets = [_]std.Target.Query{
        .{ .cpu_arch = .x86, .os_tag = .windows, .abi = .msvc },
        .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .msvc },
        .{ .cpu_arch = .aarch64, .os_tag = .windows, .abi = .msvc },
    };
    for (targets) |t| {
        const resolved = b.resolveTargetQuery(t);
        const hook = b.addLibrary(.{
            .name = "ForgeHook",
            .linkage = .dynamic,
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/ForgeHook/DllMain.zig"),
                .target = resolved,
                .optimize = .ReleaseSafe,
            }),
        });
        hook.linkLibC();
        b.installArtifact(hook);

        const cli = b.addExecutable(.{
            .name = "InstallerCli",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/InstallerCli/main.zig"),
                .target = resolved,
                .optimize = .ReleaseSafe,
            }),
        });
        b.installArtifact(cli);
    }
    const autofind_mod = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/AutoFind.zig"),
        .target = b.graph.host,
    });
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/HookTest/main.zig"),
            .target = b.graph.host,
            .imports = &.{
                .{ .name = "AutoFind", .module = autofind_mod },
            },
        }),
    });
    const run_tests = b.addRunArtifact(unit_tests);
    b.step("test", "Run HookTest unit suite").dependOn(&run_tests.step);
}
