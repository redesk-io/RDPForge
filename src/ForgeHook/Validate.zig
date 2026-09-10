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

pub const CallSite = struct { at_rva: u32, target_rva: ?u32 };

pub fn listCallsNear(code: []const u8, code_rva: u32, center_rva: u32, radius: u32, out: []CallSite) []CallSite {
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
        if (full.mnemonic == Decode.CALL and at >= center_rva -| radius and at <= center_rva +| radius) {
            var target: ?u32 = null;
            for (full.operands[0..full.op_count]) |op| {
                if (op.type == Decode.OP_IMM) {
                    const rel = op.unnamed_0.imm.value.s;
                    target = @as(u32, @truncate(@as(u64, @bitCast(@as(i64, at) + @as(i64, full.length) + rel))));
                    break;
                }
            }
            out[n] = .{ .at_rva = at, .target_rva = target };
            n += 1;
        }
        i += full.length;
    }
    return out[0..n];
}

pub const CallTo = struct { at_rva: u32 };

pub fn findCallsTo(code: []const u8, code_rva: u32, target: u32, out: []CallTo) []CallTo {
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
        if (full.mnemonic == Decode.CALL) {
            const at: u32 = code_rva + @as(u32, @intCast(i));
            for (full.operands[0..full.op_count]) |op| {
                if (op.type != Decode.OP_IMM) continue;
                const t = Decode.ripTarget(at, full.length, op.unnamed_0.imm.value.s);
                if (t == target) {
                    out[n] = .{ .at_rva = at };
                    n += 1;
                    break;
                }
            }
        }
        i += full.length;
    }
    return out[0..n];
}

pub const VersionCheckSite = struct { call_rva: u32, jz_rva: u32, jz_len: u8 };

pub fn findCallTestJz(code: []const u8, code_rva: u32) ?VersionCheckSite {
    var i: usize = 0;
    while (i < code.len) {
        const call = Decode.decodeFull64(code[i..]) orelse {
            i += 1;
            continue;
        };
        if (call.length == 0) {
            i += 1;
            continue;
        }
        if (call.mnemonic == Decode.CALL) {
            const call_rva: u32 = code_rva + @as(u32, @intCast(i));
            var j: usize = i + call.length;
            var scanned: usize = 0;
            while (j < code.len and scanned < 48) {
                const t = Decode.decodeFull64(code[j..]) orelse {
                    j += 1;
                    scanned += 1;
                    continue;
                };
                if (t.length == 0) {
                    j += 1;
                    scanned += 1;
                    continue;
                }
                if (t.mnemonic == Decode.TEST) {
                    const n_off = j + t.length;
                    if (n_off < code.len) {
                        const n = Decode.decodeFull64(code[n_off..]) orelse break;
                        if (n.length > 0 and (n.mnemonic == Decode.JZ or n.mnemonic == Decode.JNZ)) {
                            return .{
                                .call_rva = call_rva,
                                .jz_rva = code_rva + @as(u32, @intCast(n_off)),
                                .jz_len = n.length,
                            };
                        }
                    }
                    break;
                }
                j += t.length;
                scanned += t.length;
            }
        }
        i += call.length;
    }
    return null;
}

pub fn findAllCallTestJz(code: []const u8, code_rva: u32, out: []VersionCheckSite) []VersionCheckSite {
    var n: usize = 0;
    var i: usize = 0;
    while (i < code.len and n < out.len) {
        const call = Decode.decodeFull64(code[i..]) orelse {
            i += 1;
            continue;
        };
        if (call.length == 0) {
            i += 1;
            continue;
        }
        if (call.mnemonic == Decode.CALL) {
            const call_rva: u32 = code_rva + @as(u32, @intCast(i));
            var j: usize = i + call.length;
            var scanned: usize = 0;
            var matched = false;
            while (j < code.len and scanned < 48) {
                const t = Decode.decodeFull64(code[j..]) orelse {
                    j += 1;
                    scanned += 1;
                    continue;
                };
                if (t.length == 0) {
                    j += 1;
                    scanned += 1;
                    continue;
                }
                if (t.mnemonic == Decode.TEST) {
                    const n_off = j + t.length;
                    if (n_off < code.len) {
                        const nx = Decode.decodeFull64(code[n_off..]);
                        if (nx) |nn| {
                            if (nn.length > 0 and (nn.mnemonic == Decode.JZ or nn.mnemonic == Decode.JNZ)) {
                                out[n] = .{
                                    .call_rva = call_rva,
                                    .jz_rva = code_rva + @as(u32, @intCast(n_off)),
                                    .jz_len = nn.length,
                                };
                                n += 1;
                                matched = true;
                            }
                        }
                    }
                    break;
                }
                j += t.length;
                scanned += t.length;
            }
            if (matched) {
                i += call.length;
                continue;
            }
        }
        i += call.length;
    }
    return out[0..n];
}

pub const RankedSite = struct { site: VersionCheckSite, dist: u32 };

pub fn rankByLeaProximity(sites: []const VersionCheckSite, leas: []const u32, out: []RankedSite) []RankedSite {
    var n: usize = 0;
    for (sites) |s| {
        if (n >= out.len) break;
        var best: u32 = 0xFFFFFFFF;
        for (leas) |l| {
            const d: u32 = if (s.jz_rva >= l) s.jz_rva - l else l - s.jz_rva;
            if (d < best) best = d;
        }
        out[n] = .{ .site = s, .dist = best };
        n += 1;
    }
    var i: usize = 1;
    while (i < n) : (i += 1) {
        var j: usize = i;
        while (j > 0 and out[j].dist < out[j - 1].dist) {
            const t = out[j];
            out[j] = out[j - 1];
            out[j - 1] = t;
            j -= 1;
        }
    }
    return out[0..n];
}
