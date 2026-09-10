const std = @import("std");

pub const Section = struct {
    name: [8]u8,
    virtual_address: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
};

pub const Headers = struct {
    sections: []const Section,
    is_64: bool,
};

pub const PeError = error{ BadDos, BadNt, NoSections };

pub fn parseSections(image: []const u8, out: []Section) PeError![]Section {
    if (image.len < 64 or image[0] != 'M' or image[1] != 'Z') return PeError.BadDos;
    const e_lfanew = std.mem.readInt(u32, image[60..][0..4], .little);
    if (image.len < e_lfanew + 6) return PeError.BadNt;
    if (image[e_lfanew] != 'P' or image[e_lfanew + 1] != 'E') return PeError.BadNt;
    const n_sections = std.mem.readInt(u16, image[e_lfanew + 6 ..][0..2], .little);
    const opt_size = std.mem.readInt(u16, image[e_lfanew + 20 ..][0..2], .little);
    const magic = std.mem.readInt(u16, image[e_lfanew + 24 ..][0..2], .little);
    const is_64 = magic == 0x20b;
    _ = is_64;
    const sect_off = e_lfanew + 24 + @as(usize, opt_size);
    if (n_sections == 0) return PeError.NoSections;
    const count: usize = @min(@as(usize, n_sections), out.len);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const base = sect_off + i * 40;
        if (image.len < base + 40) break;
        var s: Section = undefined;
        @memcpy(&s.name, image[base ..][0..8]);
        s.virtual_size = std.mem.readInt(u32, image[base + 8 ..][0..4], .little);
        s.virtual_address = std.mem.readInt(u32, image[base + 12 ..][0..4], .little);
        s.raw_size = std.mem.readInt(u32, image[base + 16 ..][0..4], .little);
        s.raw_ptr = std.mem.readInt(u32, image[base + 20 ..][0..4], .little);
        out[i] = s;
    }
    return out[0..i];
}

pub fn findSection(sections: []const Section, name: *const [8]u8) ?Section {
    for (sections) |s| {
        if (std.mem.eql(u8, &s.name, name)) return s;
    }
    return null;
}

pub fn rvaToOffset(sections: []const Section, rva: u32) ?usize {
    for (sections) |s| {
        const size = @max(s.virtual_size, s.raw_size);
        if (rva >= s.virtual_address and rva < s.virtual_address + size) {
            return @as(usize, s.raw_ptr) + (rva - s.virtual_address);
        }
    }
    return null;
}

pub fn offsetToRva(sections: []const Section, off: usize) ?u32 {
    for (sections) |s| {
        if (off >= s.raw_ptr and off < @as(usize, s.raw_ptr) + s.raw_size) {
            return s.virtual_address + @as(u32, @intCast(off - s.raw_ptr));
        }
    }
    return null;
}
