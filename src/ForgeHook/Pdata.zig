const std = @import("std");

pub const RuntimeFunc = struct { begin: u32, end: u32, unwind: u32 };

pub const PdataError = error{ BadTable, NoMatch };

pub fn entryCount(dir_size: u32) usize {
    return dir_size / 12;
}

pub fn readEntry(image: []const u8, table_off: usize, index: usize) PdataError!RuntimeFunc {
    const base = table_off + index * 12;
    if (image.len < base + 12) return PdataError.BadTable;
    return .{
        .begin = std.mem.readInt(u32, image[base..][0..4], .little),
        .end = std.mem.readInt(u32, image[base + 4 ..][0..4], .little),
        .unwind = std.mem.readInt(u32, image[base + 8 ..][0..4], .little),
    };
}

pub fn containingFunction(image: []const u8, table_off: usize, count: usize, rva: u32) PdataError!RuntimeFunc {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const f = try readEntry(image, table_off, i);
        if (rva >= f.begin and rva < f.end) return f;
    }
    return PdataError.NoMatch;
}
