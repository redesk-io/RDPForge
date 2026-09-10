const Decode = @import("Decode");

pub const CmpSite = struct { at_rva: u32, disp: i64, base_reg: c_uint, insn_len: u8 };

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
                        .base_reg = op.unnamed_0.mem.base,
                        .insn_len = full.length,
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
                    .base_reg = op.unnamed_0.mem.base,
                    .insn_len = full.length,
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

pub const GlobalInit = struct { at_rva: u32, target_rva: u32 };

pub fn listMovMemImm1(code: []const u8, code_rva: u32, out: []GlobalInit) []GlobalInit {
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
        if (full.mnemonic == Decode.MOV and full.op_count >= 2) {
            const dst = full.operands[0];
            const src = full.operands[1];
            if (dst.type == Decode.OP_MEM and src.type == Decode.OP_IMM and src.unnamed_0.imm.value.u == 1) {
                if (dst.unnamed_0.mem.base == Decode.RIP_REG) {
                    const at: u32 = code_rva + @as(u32, @intCast(i));
                    out[n] = .{
                        .at_rva = at,
                        .target_rva = Decode.ripTarget(at, full.length, dst.unnamed_0.mem.disp.value),
                    };
                    n += 1;
                }
            }
        }
        i += full.length;
    }
    return out[0..n];
}

pub const PatchBlob = struct { bytes: [16]u8, len: u8 };

pub fn encodeDefPolicy(cmp: CmpSite, jcc_len: u8) ?PatchBlob {
    const base = Decode.regCode64(cmp.base_reg) orelse return null;
    if (base & 0x7 == 4) return null;
    const total: usize = @as(usize, cmp.insn_len) + jcc_len;
    if (total < 12 or total > 16) return null;
    if (cmp.disp < 0 or cmp.disp > 0x7FFFFFFF) return null;
    const d: u32 = @as(u32, @intCast(cmp.disp));
    const rex: bool = base >= 8;
    if (encodeMovEax(total, base, rex, d)) |b| return b;
    return encodeMovImm(total, base, rex, d);
}

fn encodeMovEax(total: usize, base: u4, rex: bool, d: u32) ?PatchBlob {
    const head: usize = 5 + (if (rex) @as(usize, 1) else 0) + 6;
    if (total < head + 2) return null;
    var out = PatchBlob{ .bytes = [_]u8{0x90} ** 16, .len = @as(u8, @intCast(total)) };
    var i: usize = 0;
    out.bytes[i] = 0xB8;
    i += 1;
    out.bytes[i] = 0x01;
    out.bytes[i + 1] = 0x00;
    out.bytes[i + 2] = 0x00;
    out.bytes[i + 3] = 0x00;
    i += 4;
    if (rex) {
        out.bytes[i] = 0x41;
        i += 1;
    }
    out.bytes[i] = 0x89;
    i += 1;
    out.bytes[i] = 0x80 | @as(u8, base & 0x7);
    i += 1;
    out.bytes[i] = @as(u8, @truncate(d));
    out.bytes[i + 1] = @as(u8, @truncate(d >> 8));
    out.bytes[i + 2] = @as(u8, @truncate(d >> 16));
    out.bytes[i + 3] = @as(u8, @truncate(d >> 24));
    i += 4;
    var k: usize = i;
    while (k < total - 2) : (k += 1) out.bytes[k] = 0x90;
    out.bytes[total - 2] = 0xEB;
    out.bytes[total - 1] = 0x00;
    return out;
}

fn encodeMovImm(total: usize, base: u4, rex: bool, d: u32) ?PatchBlob {
    const head: usize = (if (rex) @as(usize, 1) else 0) + 10;
    if (total < head + 2) return null;
    var out = PatchBlob{ .bytes = [_]u8{0x90} ** 16, .len = @as(u8, @intCast(total)) };
    var i: usize = 0;
    if (rex) {
        out.bytes[i] = 0x41;
        i += 1;
    }
    out.bytes[i] = 0xC7;
    i += 1;
    out.bytes[i] = 0x80 | @as(u8, base & 0x7);
    i += 1;
    out.bytes[i] = @as(u8, @truncate(d));
    out.bytes[i + 1] = @as(u8, @truncate(d >> 8));
    out.bytes[i + 2] = @as(u8, @truncate(d >> 16));
    out.bytes[i + 3] = @as(u8, @truncate(d >> 24));
    i += 4;
    out.bytes[i] = 0x01;
    out.bytes[i + 1] = 0x00;
    out.bytes[i + 2] = 0x00;
    out.bytes[i + 3] = 0x00;
    i += 4;
    var k: usize = i;
    while (k < total - 2) : (k += 1) out.bytes[k] = 0x90;
    out.bytes[total - 2] = 0xEB;
    out.bytes[total - 1] = 0x00;
    return out;
}

pub const BranchBlob = struct { bytes: [16]u8, len: u8 };

pub fn encodeNopFill(len: u8) ?BranchBlob {
    if (len == 0 or len > 16) return null;
    const out = BranchBlob{ .bytes = [_]u8{0x90} ** 16, .len = len };
    return out;
}

pub fn encodeNopJmp(jcc_len: u8, rel32: i64) ?BranchBlob {
    if (jcc_len < 5 or jcc_len > 16) return null;
    if (rel32 < -0x80000000 or rel32 > 0x7FFFFFFF) return null;
    var out = BranchBlob{ .bytes = [_]u8{0x90} ** 16, .len = jcc_len };
    out.bytes[0] = 0x90;
    out.bytes[1] = 0xE9;
    const r: u32 = @as(u32, @truncate(@as(u64, @bitCast(rel32))));
    out.bytes[2] = @as(u8, @truncate(r));
    out.bytes[3] = @as(u8, @truncate(r >> 8));
    out.bytes[4] = @as(u8, @truncate(r >> 16));
    out.bytes[5] = @as(u8, @truncate(r >> 24));
    return out;
}

pub fn encodeJmpShort(total_len: u8, rel8: i64) ?BranchBlob {
    if (total_len < 2 or total_len > 16) return null;
    if (rel8 < -128 or rel8 > 127) return null;
    var out = BranchBlob{ .bytes = [_]u8{0x90} ** 16, .len = total_len };
    out.bytes[0] = 0xEB;
    out.bytes[1] = @as(u8, @truncate(@as(u64, @bitCast(rel8))));
    return out;
}

pub fn encodeMovEax1(total_len: u8) ?BranchBlob {
    if (total_len < 5 or total_len > 16) return null;
    var out = BranchBlob{ .bytes = [_]u8{0x90} ** 16, .len = total_len };
    out.bytes[0] = 0xB8;
    out.bytes[1] = 0x01;
    out.bytes[2] = 0x00;
    out.bytes[3] = 0x00;
    out.bytes[4] = 0x00;
    return out;
}

pub fn encodeZero(len: u8) ?BranchBlob {
    if (len == 0 or len > 16) return null;
    const out = BranchBlob{ .bytes = [_]u8{0x00} ** 16, .len = len };
    return out;
}
