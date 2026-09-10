const std = @import("std");
const Decode = @import("Decode");

pub const Xref = struct { at_rva: u32, target_rva: u32 };

fn isLeaRip(opcode: u8, modrm: u8) bool {
    const mod: u8 = (modrm >> 6) & 0x3;
    const rm: u8 = modrm & 0x7;
    return (opcode == 0x8D) and mod == 0 and rm == 0x5;
}

pub fn matchLeaRip(code: []const u8, code_rva: u32, want_target: u32) ?Xref {
    var i: usize = 0;
    while (i + 7 <= code.len) : (i += 1) {
        const rex = code[i];
        if (rex < 0x40 or rex > 0x4F) continue;
        if (!isLeaRip(code[i + 1], code[i + 2])) continue;
        const disp = std.mem.readInt(i32, code[i + 3 ..][0..4], .little);
        const rip = @as(i64, code_rva) + @as(i64, @intCast(i)) + 7;
        const target = rip + disp;
        if (target == @as(i64, want_target)) {
            return .{ .at_rva = code_rva + @as(u32, @intCast(i)), .target_rva = want_target };
        }
        i += 6;
    }
    return null;
}

pub fn adrpAddTarget(adrp_rva: u32, adrp_word: u32, add_imm12: u32) u32 {
    const page = adrp_rva & 0xFFFFF000;
    const immhi: u32 = (adrp_word >> 5) & 0x7FFFF;
    const immlo: u32 = (adrp_word >> 29) & 0x3;
    const imm: i64 = @as(i64, @bitCast((immhi << 2) | immlo)) << 12;
    const base: i64 = @as(i64, @bitCast(page)) + imm;
    return @as(u32, @truncate(@as(i64, @bitCast(base)) + @as(i64, add_imm12)));
}

pub fn isAdrp(word: u32) bool {
    return (word & 0x9F000000) == 0x90000000;
}

pub fn isAddImm64(word: u32) bool {
    return (word & 0xFFC00000) == 0x91000000;
}

pub const prologue_x86 = [_]u8{ 0x8B, 0xFF, 0x55, 0x8B, 0xEC };

pub fn scanPrologues(code: []const u8, code_rva: u32, out: []u32) []u32 {
    var n: usize = 0;
    var i: usize = 0;
    while (i + prologue_x86.len <= code.len and n < out.len) : (i += 1) {
        if (std.mem.eql(u8, code[i .. i + prologue_x86.len], &prologue_x86)) {
            out[n] = code_rva + @as(u32, @intCast(i));
            n += 1;
            i += prologue_x86.len - 1;
        }
    }
    return out[0..n];
}

pub fn scanRipXrefs(code: []const u8, code_rva: u32, want_target: u32, out: []Xref) []Xref {
    var n: usize = 0;
    var i: usize = 0;
    while (i < code.len and n < out.len) {
        const full = Decode.decodeFull64(code[i..]) orelse {
            i += 1;
            continue;
        };
        if (full.length == 0) {
            i += 1;
            continue;
        }
        const at: u32 = code_rva + @as(u32, @intCast(i));
        for (full.operands[0..full.op_count]) |op| {
            if (op.type != Decode.OP_MEM) continue;
            if (op.unnamed_0.mem.base != Decode.RIP_REG) continue;
            if (Decode.ripTarget(at, full.length, op.unnamed_0.mem.disp.value) == want_target) {
                out[n] = .{ .at_rva = at, .target_rva = want_target };
                n += 1;
                break;
            }
        }
        i += full.length;
    }
    return out[0..n];
}
