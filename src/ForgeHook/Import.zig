const std = @import("std");
const Pe = @import("Pe");
const NtHeaders = @import("NtHeaders");

pub const Import = struct { dll_off: usize, sym_off: usize, iat_rva: u32 };

pub const ImportError = error{ BadTable, NoImportDir, Truncated };

pub fn findSymbol(
    image: []const u8,
    sections: []const Pe.Section,
    dll_sub: []const u8,
    sym_name: []const u8,
    out: []Import,
) ImportError![]Import {
    const info = NtHeaders.ntInfo(image) catch return ImportError.BadTable;
    const dir = NtHeaders.dataDir(image, info, 1) catch return ImportError.NoImportDir;
    if (dir.rva == 0 or dir.size == 0) return ImportError.NoImportDir;
    const table = Pe.rvaToOffset(sections, dir.rva) orelse return ImportError.BadTable;
    const is_64 = info.is_64;
    const thunk_size: usize = if (is_64) 8 else 4;
    var n: usize = 0;
    var d: usize = 0;
    while (true) : (d += 20) {
        const base = table + d;
        if (image.len < base + 20) return ImportError.Truncated;
        const name_rva = std.mem.readInt(u32, image[base + 12 ..][0..4], .little);
        if (name_rva == 0 and d > 0) {
            var all_zero = true;
            for (image[base .. base + 20]) |b| {
                if (b != 0) {
                    all_zero = false;
                    break;
                }
            }
            if (all_zero) break;
        }
        const first_thunk = std.mem.readInt(u32, image[base + 16 ..][0..4], .little);
        const orig_thunk = std.mem.readInt(u32, image[base ..][0..4], .little);
        const thunk_rva = if (orig_thunk != 0) orig_thunk else first_thunk;
        if (name_rva == 0 or thunk_rva == 0) continue;
        const name_off = Pe.rvaToOffset(sections, name_rva) orelse continue;
        const dll_end = std.mem.indexOfScalar(u8, image[name_off..], 0) orelse continue;
        const dll_name = image[name_off .. name_off + dll_end];
        var match_dll = false;
        if (dll_sub.len == 0) {
            match_dll = true;
        } else {
            if (std.ascii.indexOfIgnoreCase(dll_name, dll_sub) != null) match_dll = true;
        }
        if (!match_dll) continue;
        var t: usize = 0;
        while (true) : (t += thunk_size) {
            const thunk_off = Pe.rvaToOffset(sections, thunk_rva) orelse break;
            if (image.len < thunk_off + t + thunk_size) break;
            const val: u64 = if (is_64)
                std.mem.readInt(u64, image[thunk_off + t ..][0..8], .little)
            else
                std.mem.readInt(u32, image[thunk_off + t ..][0..4], .little);
            if (val == 0) break;
            const ordinal_bit: u64 = if (is_64) 0x8000000000000000 else 0x80000000;
            if (val & ordinal_bit != 0) continue;
            const hint_name_rva: u32 = @as(u32, @truncate(val));
            const hn_off = Pe.rvaToOffset(sections, hint_name_rva) orelse continue;
            if (image.len < hn_off + 2 + sym_name.len + 1) continue;
            if (!std.mem.eql(u8, image[hn_off + 2 .. hn_off + 2 + sym_name.len], sym_name)) continue;
            if (image[hn_off + 2 + sym_name.len] != 0) continue;
            if (n >= out.len) return out[0..n];
            const iat_off = Pe.rvaToOffset(sections, first_thunk) orelse continue;
            out[n] = .{
                .dll_off = name_off,
                .sym_off = hn_off + 2,
                .iat_rva = first_thunk + @as(u32, @intCast(t)),
            };
            _ = iat_off;
            n += 1;
        }
    }
    return out[0..n];
}
