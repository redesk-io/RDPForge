const Decode = @import("Decode");

pub const CmpSite = struct { at_rva: u32, disp: i64 };

pub fn findCmpMemDisp(code: []const u8, code_rva: u32, disp_want: i64) ?CmpSite {    var i: usize = 0;
    while (i < code.len) {
        const full = Decode.decodeFull64(code[i..]) orelse {
            i += 1;
            continue;
        };
        if (full.length == 0) {
            i += 1;
            continue;
        }
        if (full.mnemonic == Decode.CMP) {
            for (full.operands[0..full.op_count]) |op| {
                if (op.type != Decode.OP_MEM) continue;
                if (op.unnamed_0.mem.disp.value == disp_want) {
                    return .{
                        .at_rva = code_rva + @as(u32, @intCast(i)),
                        .disp = disp_want,
                    };
                }
            }
        }
        i += full.length;
    }
    return null;
}

pub fn listCmpMemDisps(code: []const u8, code_rva: u32, out: []CmpSite) []CmpSite {
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
        if (full.mnemonic == Decode.CMP) {
            for (full.operands[0..full.op_count]) |op| {
                if (op.type != Decode.OP_MEM) continue;
                out[n] = .{
                    .at_rva = code_rva + @as(u32, @intCast(i)),
                    .disp = op.unnamed_0.mem.disp.value,
                };
                n += 1;
                break;
            }
        }
        i += full.length;
    }
    return out[0..n];
}

pub const DefPolicySite = struct { cmp_rva: u32, jcc_rva: u32, jcc_len: u8 };

pub fn findDefPolicySite(code: []const u8, code_rva: u32) ?DefPolicySite {
    const cmp = findCmpMemDisp(code, code_rva, 0x63C) orelse return null;
    var off: usize = @as(usize, cmp.at_rva - code_rva);
    const start = off;
    var scanned: usize = 0;
    while (off < code.len and scanned < 64) {
        const full = Decode.decodeFull64(code[off..]) orelse {
            off += 1;
            scanned += 1;
            continue;
        };
        if (full.length == 0) {
            off += 1;
            scanned += 1;
            continue;
        }
        if (off > start and (full.mnemonic == Decode.JZ or full.mnemonic == Decode.JNZ)) {
            return .{
                .cmp_rva = cmp.at_rva,
                .jcc_rva = code_rva + @as(u32, @intCast(off)),
                .jcc_len = full.length,
            };
        }
        off += full.length;
        scanned += full.length;
    }
    return null;
}
