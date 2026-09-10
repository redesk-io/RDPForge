const std = @import("std");
const AutoFind = @import("AutoFind");
const Pe = @import("Pe");
const Anchors = @import("Anchors");
const Decode = @import("Decode");
const NtHeaders = @import("NtHeaders");
const Pdata = @import("Pdata");
const Xref = @import("Xref");

test "emissions must be <= 16 bytes (R3 gate)" {
    const e = AutoFind.Emission{ .site = .def_policy, .rva = 0x1234, .len = 16 };
    try std.testing.expect(AutoFind.validateEmission(e));
    const bad = AutoFind.Emission{ .site = .def_policy, .rva = 0x1234, .len = 17 };
    try std.testing.expect(!AutoFind.validateEmission(bad));
}

test "zydis decodes LEA r64,[RIP+disp] as 7 bytes" {
    const code = [_]u8{ 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00 };
    const insn = Decode.decode64(&code, 0x1000) orelse return error.DecodeFailed;
    try std.testing.expect(insn.length == 7);
    try std.testing.expect(insn.mnemonic == Decode.LEA);
}

test "discovery classification: miss / validation_fail / found" {
    try std.testing.expect(AutoFind.classify(false, false) == .miss);
    try std.testing.expect(AutoFind.classify(true, false) == .validation_fail);
    try std.testing.expect(AutoFind.classify(true, true) == .found);
}

test "anchor scan finds planted marker, misses absent one" {
    var buf: [256]u8 = [_]u8{0} ** 256;
    const marker = "CDefPolicy::Query";
    @memcpy(buf[100 .. 100 + marker.len], marker);
    try std.testing.expect(Anchors.findAnchor(&buf, marker, 4) == 100);
    try std.testing.expect(Anchors.findAnchor(&buf, "IsAllowNonRDPStack", 4) == null);
    try std.testing.expect(Anchors.findAnchor(&buf, "", 4) == null);
}

test "pe parser reads synthetic section table" {
    var img: [512]u8 = [_]u8{0} ** 512;
    img[0] = 'M';
    img[1] = 'Z';
    std.mem.writeInt(u32, img[60..64], 128, .little);
    img[128] = 'P';
    img[129] = 'E';
    std.mem.writeInt(u16, img[128 + 6 .. 128 + 8], 1, .little);
    std.mem.writeInt(u16, img[128 + 20 .. 128 + 22], 32, .little);
    std.mem.writeInt(u16, img[128 + 24 .. 128 + 26], 0x20b, .little);
    const base = 128 + 24 + 32;
    @memcpy(img[base .. base + 5], ".text");
    std.mem.writeInt(u32, img[base + 8 .. base + 12], 0x100, .little);
    std.mem.writeInt(u32, img[base + 12 .. base + 16], 0x1000, .little);
    std.mem.writeInt(u32, img[base + 16 .. base + 20], 0x200, .little);
    std.mem.writeInt(u32, img[base + 20 .. base + 24], 0x200, .little);
    var out: [4]Pe.Section = undefined;
    const sections = try Pe.parseSections(&img, &out);
    try std.testing.expect(sections.len == 1);
    var name: [8]u8 = [_]u8{0} ** 8;
    @memcpy(name[0..5], ".text");
    try std.testing.expect(Pe.findSection(sections, &name) != null);
    try std.testing.expect(Pe.rvaToOffset(sections, 0x1010) == 0x200 + 0x10);
    try std.testing.expect(Pe.rvaToOffset(sections, 0x9999) == null);
}

test "x64 LEA RIP resolver hits planted xref" {
    var code: [32]u8 = [_]u8{0xCC} ** 32;
    code[4] = 0x48;
    code[5] = 0x8D;
    code[6] = 0x0D;
    const code_rva: u32 = 0x1000;
    const want: u32 = 0x2000;
    const disp: i32 = @as(i32, @bitCast(want)) - (@as(i32, @bitCast(code_rva)) + 4 + 7);
    std.mem.writeInt(i32, code[7..][0..4], disp, .little);
    const hit = Xref.matchLeaRip(&code, code_rva, want);
    try std.testing.expect(hit != null);
    try std.testing.expect(hit.?.at_rva == code_rva + 4);
    try std.testing.expect(Xref.matchLeaRip(&code, code_rva, 0x9999) == null);
}

test "x86 prologue scanner enumerates two functions" {
    var code: [32]u8 = [_]u8{0x90} ** 32;
    @memcpy(code[2..][0..5], &Xref.prologue_x86);
    @memcpy(code[20..][0..5], &Xref.prologue_x86);
    var out: [8]u32 = undefined;
    const found = Xref.scanPrologues(&code, 0x5000, &out);
    try std.testing.expect(found.len == 2);
    try std.testing.expect(found[0] == 0x5002);
    try std.testing.expect(found[1] == 0x5014);
}

test "arm64 adrp/add predicate sanity" {
    try std.testing.expect(Xref.isAdrp(0x90000001));
    try std.testing.expect(!Xref.isAdrp(0x91000001));
    try std.testing.expect(Xref.isAddImm64(0x91000001));
    try std.testing.expect(!Xref.isAddImm64(0x90000001));
}

test "pdata containing-function lookup" {
    var table: [24]u8 = [_]u8{0} ** 24;
    std.mem.writeInt(u32, table[0..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, table[4..][0..4], 0x1100, .little);
    std.mem.writeInt(u32, table[12..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, table[16..][0..4], 0x2200, .little);
    const f = try Pdata.containingFunction(&table, 0, 2, 0x2050);
    try std.testing.expect(f.begin == 0x2000);
    try std.testing.expect(Pdata.containingFunction(&table, 0, 2, 0x9999) == error.NoMatch);
}

test "live termsrv.dll headers + anchor (read-only, skipped if absent)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    const n = buf.len;
    const info = try NtHeaders.ntInfo(buf[0..n]);
    try std.testing.expect(info.machine == .x64);
    try std.testing.expect(info.is_64);
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf[0..n], &secs);
    try std.testing.expect(sections.len == 8);
    var rdata_name: [8]u8 = [_]u8{0} ** 8;
    @memcpy(rdata_name[0..6], ".rdata");
    _ = Pe.findSection(sections, &rdata_name) orelse return error.MissingRdata;
    try std.testing.expect(Anchors.findAnchor(buf[0..n], "CDefPolicy::Query", 1) != null);
    try std.testing.expect(Anchors.findAnchor(buf[0..n], "IsSingleSessionPerUser", 1) != null);
}

test "scanRipXrefs finds planted LEA xref" {
    var code: [32]u8 = [_]u8{0x90} ** 32;
    code[4] = 0x48;
    code[5] = 0x8D;
    code[6] = 0x0D;
    const code_rva: u32 = 0x1000;
    const want: u32 = 0x2000;
    const disp: i32 = @as(i32, @bitCast(want)) - (@as(i32, @bitCast(code_rva)) + 4 + 7);
    std.mem.writeInt(i32, code[7..][0..4], disp, .little);
    var out: [8]Xref.Xref = undefined;
    const found = Xref.scanRipXrefs(&code, code_rva, want, &out);
    try std.testing.expect(found.len == 1);
    try std.testing.expect(found[0].at_rva == code_rva + 4);
    const none = Xref.scanRipXrefs(&code, code_rva, 0x9999, &out);
    try std.testing.expect(none.len == 0);
}

test "live termsrv.dll: RIP xrefs to CDefPolicy::Query string (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    const anchor_off = Anchors.findAnchor(buf, "CDefPolicy::Query", 1) orelse return error.AnchorMissing;
    const anchor_rva = Pe.offsetToRva(sections, anchor_off) orelse return error.AnchorUnmapped;
    var text_name: [8]u8 = [_]u8{0} ** 8;
    @memcpy(text_name[0..5], ".text");
    const text = Pe.findSection(sections, &text_name) orelse return error.MissingText;
    const code = buf[text.raw_ptr .. text.raw_ptr + text.raw_size];
    var out: [4096]Xref.Xref = undefined;
    const found = Xref.scanRipXrefs(code, text.virtual_address, anchor_rva, &out);
    std.debug.print("xrefs to CDefPolicy::Query: {d}\n", .{found.len});
    try std.testing.expect(found.len > 0);
}

test "live termsrv.dll: anchor to function to DefPolicy CMP (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    const Validate = @import("Validate");
    const anchor_off = Anchors.findAnchor(buf, "CDefPolicy::Query", 1) orelse return error.AnchorMissing;
    const anchor_rva = Pe.offsetToRva(sections, anchor_off) orelse return error.AnchorUnmapped;
    var text_name: [8]u8 = [_]u8{0} ** 8;
    @memcpy(text_name[0..5], ".text");
    const text = Pe.findSection(sections, &text_name) orelse return error.MissingText;
    const code = buf[text.raw_ptr .. text.raw_ptr + text.raw_size];
    var out: [4096]Xref.Xref = undefined;
    const found = Xref.scanRipXrefs(code, text.virtual_address, anchor_rva, &out);
    try std.testing.expect(found.len > 0);
    const func = try Pdata.containingFunctionForRva(buf, sections, found[0].at_rva);
    std.debug.print("CDefPolicy::Query-ish func: begin={x} end={x} len={d}\n", .{ func.begin, func.end, func.end - func.begin });
    try std.testing.expect(func.begin <= found[0].at_rva);
    try std.testing.expect(func.end > found[0].at_rva);
    try std.testing.expect(func.end - func.begin < 0x10000);
    const f_off = Pe.rvaToOffset(sections, func.begin) orelse return error.FuncUnmapped;
    const f_end = Pe.rvaToOffset(sections, func.end) orelse return error.FuncEndUnmapped;
    const site = Validate.findCmpMemDisp(buf[f_off..f_end], func.begin, 0x63C);
    if (site) |s| {
        std.debug.print("DefPolicy CMP [base+63C] at={x}\n", .{s.at_rva});
    } else {
        std.debug.print("DefPolicy CMP [base+63C]: not in xref func\n", .{});
    }
}

test "live termsrv.dll: CMP census of xref function (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    const Validate = @import("Validate");
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    const f_off = Pe.rvaToOffset(sections, 0xa34d0) orelse return error.FuncUnmapped;
    const f_end = Pe.rvaToOffset(sections, 0xa3550) orelse return error.FuncEndUnmapped;
    var out: [32]Validate.CmpSite = undefined;
    const sites = Validate.listCmpMemDisps(buf[f_off..f_end], 0xa34d0, &out);
    for (sites) |s| std.debug.print("cmp at={x} disp={x}\n", .{ s.at_rva, s.disp });
    std.debug.print("cmp count={d}\n", .{sites.len});
}

test "live termsrv.dll: all anchor occurrences and their xrefs (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    const Validate = @import("Validate");
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    var occ: [16]usize = undefined;
    const all = Anchors.findAllAnchors(buf, "CDefPolicy::Query", &occ);
    try std.testing.expect(all.len == 2);
    var text_name: [8]u8 = [_]u8{0} ** 8;
    @memcpy(text_name[0..5], ".text");
    const text = Pe.findSection(sections, &text_name) orelse return error.MissingText;
    var fothk_name: [8]u8 = [_]u8{0} ** 8;
    @memcpy(fothk_name[0..5], "fothk");
    const fothk = Pe.findSection(sections, &fothk_name);
    for (all) |off| {
        const rva = Pe.offsetToRva(sections, off) orelse continue;
        var out: [4096]Xref.Xref = undefined;
        const code = buf[text.raw_ptr .. text.raw_ptr + text.raw_size];
        const found = Xref.scanRipXrefs(code, text.virtual_address, rva, &out);
        std.debug.print("anchor off={x} rva={x} text-xrefs={d}\n", .{ off, rva, found.len });
        for (found) |x| {
            const func = Pdata.containingFunctionForRva(buf, sections, x.at_rva) catch continue;
            const f_off = Pe.rvaToOffset(sections, func.begin) orelse continue;
            const f_end = Pe.rvaToOffset(sections, func.end) orelse continue;
            var cmps: [64]Validate.CmpSite = undefined;
            const sites = Validate.listCmpMemDisps(buf[f_off..f_end], func.begin, &cmps);
            std.debug.print("  xref at={x} func=[{x},{x}) cmps={d}\n", .{ x.at_rva, func.begin, func.end, sites.len });
            for (sites) |s| std.debug.print("    cmp at={x} disp={x}\n", .{ s.at_rva, s.disp });
        }
        if (fothk) |fk| {
            const fcode = buf[fk.raw_ptr .. fk.raw_ptr + fk.raw_size];
            const ffound = Xref.scanRipXrefs(fcode, fk.virtual_address, rva, &out);
            std.debug.print("anchor off={x} fothk-xrefs={d}\n", .{ off, ffound.len });
        }
    }
}

test "live termsrv.dll: DefPolicy CMP signature census (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    const Validate = @import("Validate");
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    var text_name: [8]u8 = [_]u8{0} ** 8;
    @memcpy(text_name[0..5], ".text");
    const text = Pe.findSection(sections, &text_name) orelse return error.MissingText;
    const code = buf[text.raw_ptr .. text.raw_ptr + text.raw_size];
    var out: [8192]Validate.CmpSite = undefined;
    const sites = Validate.listCmpMemDisps(code, text.virtual_address, &out);
    var n63c: usize = 0;
    var n638: usize = 0;
    for (sites) |s| {
        if (s.disp == 0x63C) n63c += 1;
        if (s.disp == 0x638) n638 += 1;
    }
    std.debug.print("cmp-mem total={d} disp63C={d} disp638={d}\n", .{ sites.len, n63c, n638 });
    var shown: usize = 0;
    for (sites) |s| {
        if (s.disp != 0x63C and s.disp != 0x638) continue;
        if (shown >= 8) break;
        const func = Pdata.containingFunctionForRva(buf, sections, s.at_rva) catch continue;
        std.debug.print("  cmp at={x} disp={x} func=[{x},{x})\n", .{ s.at_rva, s.disp, func.begin, func.end });
        shown += 1;
    }
}

test "live termsrv.dll: DefPolicy site validates (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    const Validate = @import("Validate");
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    const f_off = Pe.rvaToOffset(sections, 0x6a52c) orelse return error.FuncUnmapped;
    const f_end = Pe.rvaToOffset(sections, 0x6a66e) orelse return error.FuncEndUnmapped;
    const site = Validate.findDefPolicySite(buf[f_off..f_end], 0x6a52c) orelse return error.SiteMissing;
    std.debug.print("DefPolicy site: cmp={x} jcc={x} len={d}\n", .{ site.cmp_rva, site.jcc_rva, site.jcc_len });
    try std.testing.expect(site.cmp_rva == 0x6a5c9);
    try std.testing.expect(site.jcc_rva == 0x6a5d0);
}

test "live termsrv.dll: LocalOnly anchor xref census (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    var text_name: [8]u8 = [_]u8{0} ** 8;
    @memcpy(text_name[0..5], ".text");
    const text = Pe.findSection(sections, &text_name) orelse return error.MissingText;
    const code = buf[text.raw_ptr .. text.raw_ptr + text.raw_size];
    const markers = [_][]const u8{ "GetInstanceOfTSLicense", "IsLicenseTypeLocalOnly", "IsTerminalTypeLocalOnly" };
    for (markers) |m| {
        var occ: [16]usize = undefined;
        const all = Anchors.findAllAnchors(buf, m, &occ);
        for (all) |off| {
            const rva = Pe.offsetToRva(sections, off) orelse continue;
            var out: [1024]Xref.Xref = undefined;
            const found = Xref.scanRipXrefs(code, text.virtual_address, rva, &out);
            std.debug.print("{s} off={x} rva={x} xrefs={d}\n", .{ m, off, rva, found.len });
            for (found) |x| {
                const func = Pdata.containingFunctionForRva(buf, sections, x.at_rva) catch continue;
                std.debug.print("  xref at={x} func=[{x},{x})\n", .{ x.at_rva, func.begin, func.end });
            }
        }
    }
}

test "live termsrv.dll: LocalOnly candidate windows (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    const at_list = [_]u32{ 0xbbf5d, 0xbc021, 0xbc0c1, 0xbc1c7 };
    for (at_list) |at| {
        const off = Pe.rvaToOffset(sections, at) orelse continue;
        std.debug.print("--- window at {x} ---\n", .{at});
        var i: usize = 0;
        var shown: usize = 0;
        while (i < 96 and shown < 12) {
            const full = Decode.decodeFull64(buf[off + i .. off + 128]) orelse {
                i += 1;
                continue;
            };
            if (full.length == 0) {
                i += 1;
                continue;
            }
            std.debug.print("  {x}: mnem={d} len={d}\n", .{ at + @as(u32, @intCast(i)), full.mnemonic, full.length });
            i += full.length;
            shown += 1;
        }
    }
}

test "live termsrv.dll: CALLs near LocalOnly LEAs (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    const Validate = @import("Validate");
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    const func_begin: u32 = 0xbbea0;
    const func_end: u32 = 0xc24b2;
    const f_off = Pe.rvaToOffset(sections, func_begin) orelse return error.FuncUnmapped;
    const f_end = Pe.rvaToOffset(sections, func_end) orelse return error.FuncEndUnmapped;
    const centers = [_]u32{ 0xbbf5d, 0xbc021, 0xbc0c1, 0xbc1c7 };
    for (centers) |c| {
        var out: [32]Validate.CallSite = undefined;
        const calls = Validate.listCallsNear(buf[f_off..f_end], func_begin, c, 256, &out);
        std.debug.print("calls near {x}: {d}\n", .{ c, calls.len });
        for (calls) |cs| {
            if (cs.target_rva) |t| {
                const tf = Pdata.containingFunctionForRva(buf, sections, t) catch {
                    std.debug.print("  call at={x} -> {x} (no func)\n", .{ cs.at_rva, t });
                    continue;
                };
                std.debug.print("  call at={x} -> {x} func=[{x},{x})\n", .{ cs.at_rva, t, tf.begin, tf.end });
            } else {
                std.debug.print("  call at={x} -> indirect\n", .{cs.at_rva});
            }
        }
    }
}
