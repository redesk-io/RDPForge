const std = @import("std");

pub const Machine = enum(u16) { x86 = 0x14c, x64 = 0x8664, arm64 = 0xaa64, unknown = 0 };

pub const DataDir = struct { rva: u32, size: u32 };

pub const NtInfo = struct {
    e_lfanew: usize,
    machine: Machine,
    is_64: bool,
    n_sections: u16,
    sect_off: usize,
};

pub const PeError = error{ BadDos, BadNt, NoSections, NoDataDir };

pub fn ntInfo(image: []const u8) PeError!NtInfo {
    if (image.len < 64 or image[0] != 'M' or image[1] != 'Z') return PeError.BadDos;
    const e = std.mem.readInt(u32, image[60..][0..4], .little);
    if (image.len < e + 26) return PeError.BadNt;
    if (image[e] != 'P' or image[e + 1] != 'E') return PeError.BadNt;
    const raw_machine = std.mem.readInt(u16, image[e + 4 ..][0..2], .little);
    const machine: Machine = switch (raw_machine) {
        0x14c => .x86,
        0x8664 => .x64,
        0xaa64 => .arm64,
        else => .unknown,
    };
    const n_sections = std.mem.readInt(u16, image[e + 6 ..][0..2], .little);
    const opt_size = std.mem.readInt(u16, image[e + 20 ..][0..2], .little);
    const magic = std.mem.readInt(u16, image[e + 24 ..][0..2], .little);
    if (n_sections == 0) return PeError.NoSections;
    return .{
        .e_lfanew = e,
        .machine = machine,
        .is_64 = magic == 0x20b,
        .n_sections = n_sections,
        .sect_off = e + 24 + @as(usize, opt_size),
    };
}

pub fn dataDir(image: []const u8, info: NtInfo, index: u8) PeError!DataDir {
    const opt = info.e_lfanew + 24;
    const base = if (info.is_64) opt + 112 else opt + 96;
    const off = base + @as(usize, index) * 8;
    if (image.len < off + 8) return PeError.NoDataDir;
    return .{
        .rva = std.mem.readInt(u32, image[off..][0..4], .little),
        .size = std.mem.readInt(u32, image[off + 4 ..][0..4], .little),
    };
}

pub const exception_dir_index: u8 = 3;
