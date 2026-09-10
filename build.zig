const std = @import("std");

const zydis_sources = [_][]const u8{
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
};

fn zydisLib(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = "zydis",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    lib.addCSourceFiles(.{
        .files = &zydis_sources,
        .flags = &.{
            "-DZYDIS_DISABLE_ENCODER",
            "-DZYDIS_DISABLE_FORMATTER",
            "-DZYDIS_STATIC_BUILD",
            "-DZYCORE_STATIC_BUILD",
        },
    });
    lib.addIncludePath(b.path("third_party/zydis/include"));
    lib.addIncludePath(b.path("third_party/zydis/src"));
    lib.addIncludePath(b.path("third_party/zydis/dependencies/zycore/include"));
    return lib;
}

const Mods = struct {
    site: *std.Build.Module,
    decode: *std.Build.Module,
    pe: *std.Build.Module,
    anchors: *std.Build.Module,
    ntheaders: *std.Build.Module,
    pdata: *std.Build.Module,
    xref: *std.Build.Module,
    validate: *std.Build.Module,
    import: *std.Build.Module,
    autofind: *std.Build.Module,
    patch: *std.Build.Module,
    args: *std.Build.Module,
    plan: *std.Build.Module,
    backend: *std.Build.Module,
};

fn modules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) Mods {
    const site = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Site.zig"),
        .target = target,
        .optimize = optimize,
    });
    const decode = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Decode.zig"),
        .target = target,
        .optimize = optimize,
    });
    decode.addIncludePath(b.path("third_party/zydis/include"));
    decode.addIncludePath(b.path("third_party/zydis/dependencies/zycore/include"));
    const pe = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Pe.zig"),
        .target = target,
        .optimize = optimize,
    });
    const anchors = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Anchors.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Site", .module = site },
        },
    });
    const ntheaders = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/NtHeaders.zig"),
        .target = target,
        .optimize = optimize,
    });
    const pdata = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Pdata.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Pe", .module = pe },
            .{ .name = "NtHeaders", .module = ntheaders },
        },
    });
    const xref = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Xref.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Decode", .module = decode },
        },
    });
    const validate = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Validate.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Decode", .module = decode },
        },
    });
    const import = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Import.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Pe", .module = pe },
            .{ .name = "NtHeaders", .module = ntheaders },
        },
    });
    const autofind = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/AutoFind.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Site", .module = site },
            .{ .name = "Pe", .module = pe },
            .{ .name = "Anchors", .module = anchors },
            .{ .name = "Decode", .module = decode },
            .{ .name = "Pdata", .module = pdata },
            .{ .name = "Xref", .module = xref },
            .{ .name = "Validate", .module = validate },
        },
    });
    const patch = b.createModule(.{
        .root_source_file = b.path("src/ForgeHook/Patch.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "AutoFind", .module = autofind },
        },
    });
    const args = b.createModule(.{
        .root_source_file = b.path("src/InstallerCli/Args.zig"),
        .target = target,
        .optimize = optimize,
    });
    const plan = b.createModule(.{
        .root_source_file = b.path("src/InstallerCli/Plan.zig"),
        .target = target,
        .optimize = optimize,
    });
    const backend = b.createModule(.{
        .root_source_file = b.path("src/InstallerCli/Backend.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "Plan", .module = plan },
            .{ .name = "Args", .module = args },
        },
    });
    return .{
        .site = site,
        .decode = decode,
        .pe = pe,
        .anchors = anchors,
        .ntheaders = ntheaders,
        .pdata = pdata,
        .xref = xref,
        .validate = validate,
        .import = import,
        .autofind = autofind,
        .patch = patch,
        .args = args,
        .plan = plan,
        .backend = backend,
    };
}

pub fn build(b: *std.Build) void {
    const targets = [_]std.Target.Query{
        .{ .cpu_arch = .x86, .os_tag = .windows, .abi = .gnu },
        .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
        .{ .cpu_arch = .aarch64, .os_tag = .windows, .abi = .gnu },
    };
    for (targets) |t| {
        const resolved = b.resolveTargetQuery(t);
        const m = modules(b, resolved, .ReleaseSafe);
        const zydis = zydisLib(b, resolved, .ReleaseSafe);
        const hook = b.addLibrary(.{
            .name = "ForgeHook",
            .linkage = .dynamic,
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/ForgeHook/DllMain.zig"),
                .target = resolved,
                .optimize = .ReleaseSafe,
                .imports = &.{
                    .{ .name = "Patch", .module = m.patch },
                },
            }),
        });
        hook.linkLibrary(zydis);
        b.installArtifact(hook);

        const cli = b.addExecutable(.{
            .name = "InstallerCli",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/InstallerCli/main.zig"),
                .target = resolved,
                .optimize = .ReleaseSafe,
                .imports = &.{
                    .{ .name = "Args", .module = m.args },
                    .{ .name = "Backend", .module = m.backend },
                },
            }),
        });
        b.installArtifact(cli);
    }
    const host = b.graph.host;
    const hm = modules(b, host, .Debug);
    const zydis = zydisLib(b, host, .ReleaseSafe);
    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/HookTest/main.zig"),
            .target = host,
            .imports = &.{
                .{ .name = "AutoFind", .module = hm.autofind },
                .{ .name = "Decode", .module = hm.decode },
                .{ .name = "Pe", .module = hm.pe },
                .{ .name = "Anchors", .module = hm.anchors },
                .{ .name = "NtHeaders", .module = hm.ntheaders },
                .{ .name = "Pdata", .module = hm.pdata },
                .{ .name = "Xref", .module = hm.xref },
                .{ .name = "Validate", .module = hm.validate },
                .{ .name = "Import", .module = hm.import },
                .{ .name = "Patch", .module = hm.patch },
            },
        }),
    });
    unit_tests.linkLibrary(zydis);
    const run_tests = b.addRunArtifact(unit_tests);
    b.step("test", "Run HookTest unit suite").dependOn(&run_tests.step);
    const installer_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/InstallerTest/main.zig"),
            .target = host,
            .imports = &.{
                .{ .name = "Args", .module = hm.args },
                .{ .name = "Plan", .module = hm.plan },
            },
        }),
    });
    const run_installer_tests = b.addRunArtifact(installer_tests);
    b.step("test-installer", "Run InstallerTest suite").dependOn(&run_installer_tests.step);
}
