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
    const zydis = b.addLibrary(.{
        .name = "zydis",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
            .link_libc = true,
        }),
    });
    zydis.addCSourceFiles(.{
        .files = &.{
            "third_party/zydis/src/Decoder.c",
            "third_party/zydis/src/DecoderData.c",
            "third_party/zydis/src/SharedData.c",
            "third_party/zydis/src/MetaInfo.c",
            "third_party/zydis/src/Mnemonic.c",
            "third_party/zydis/src/Register.c",
            "third_party/zydis/src/Segment.c",
            "third_party/zydis/src/String.c",
            "third_party/zydis/src/Utils.c",
            "third_party/zydis/src/Zydis.c",
            "third_party/zydis/dependencies/zycore/src/Allocator.c",
            "third_party/zydis/dependencies/zycore/src/List.c",
            "third_party/zydis/dependencies/zycore/src/String.c",
            "third_party/zydis/dependencies/zycore/src/Vector.c",
            "third_party/zydis/dependencies/zycore/src/Zycore.c",
        },
        .flags = &.{
            "-DZYDIS_DISABLE_ENCODER",
            "-DZYDIS_DISABLE_FORMATTER",
            "-DZYCORE_STATIC_DEFINE",
        },
    });
    zydis.addIncludePath(b.path("third_party/zydis/include"));
    zydis.addIncludePath(b.path("third_party/zydis/src"));
    zydis.addIncludePath(b.path("third_party/zydis/dependencies/zycore/include"));
    const decode_mod = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Decode.zig"),
        .target = b.graph.host,
    });
    decode_mod.addIncludePath(b.path("third_party/zydis/include"));
    decode_mod.addIncludePath(b.path("third_party/zydis/dependencies/zycore/include"));
    const autofind_mod = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/AutoFind.zig"),
        .target = b.graph.host,
    });
    const args_mod = b.createModule(.{
        .root_source_file = b.path("src/InstallerCli/Args.zig"),
        .target = b.graph.host,
    });
    const plan_mod = b.createModule(.{
        .root_source_file = b.path("src/InstallerCli/Plan.zig"),
        .target = b.graph.host,
    });
    const installer_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/InstallerTest/main.zig"),
            .target = b.graph.host,
            .imports = &.{
                .{ .name = "Args", .module = args_mod },
                .{ .name = "Plan", .module = plan_mod },
            },
        }),
    });
    const run_installer_tests = b.addRunArtifact(installer_tests);
    b.step("test-installer", "Run InstallerTest suite").dependOn(&run_installer_tests.step);
    const pe_mod = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Pe.zig"),
        .target = b.graph.host,
    });
    const anchors_mod = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Anchors.zig"),
        .target = b.graph.host,
        .imports = &.{
            .{ .name = "AutoFind", .module = autofind_mod },
        },
    });
    const ntheaders_mod = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/NtHeaders.zig"),
        .target = b.graph.host,
    });
    const pdata_mod = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Pdata.zig"),
        .target = b.graph.host,
    });
    const xref_mod = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Xref.zig"),
        .target = b.graph.host,
        .imports = &.{
            .{ .name = "Decode", .module = decode_mod },
        },
    });
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/HookTest/main.zig"),
            .target = b.graph.host,
            .imports = &.{
                .{ .name = "AutoFind", .module = autofind_mod },
                .{ .name = "Decode", .module = decode_mod },
                .{ .name = "Pe", .module = pe_mod },
                .{ .name = "Anchors", .module = anchors_mod },
                .{ .name = "NtHeaders", .module = ntheaders_mod },
                .{ .name = "Pdata", .module = pdata_mod },
                .{ .name = "Xref", .module = xref_mod },
            },
        }),
    });
    unit_tests.linkLibrary(zydis);
    const run_tests = b.addRunArtifact(unit_tests);
    b.step("test", "Run HookTest unit suite").dependOn(&run_tests.step);
}
