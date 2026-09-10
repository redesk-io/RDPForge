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

test "live termsrv.dll: import census for memset/VerifyVersionInfoW (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    const Import = @import("Import");
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    var out: [8]Import.Import = undefined;
    const memset = try Import.findSymbol(buf, sections, "crt-string", "memset", &out);
    std.debug.print("memset imports: {d}\n", .{memset.len});
    for (memset) |m| std.debug.print("  iat_rva={x}\n", .{m.iat_rva});
    var out2: [8]Import.Import = undefined;
    const vv = try Import.findSymbol(buf, sections, "kernel32", "VerifyVersionInfoW", &out2);
    std.debug.print("VerifyVersionInfoW imports: {d}\n", .{vv.len});
    for (vv) |m| std.debug.print("  iat_rva={x}\n", .{m.iat_rva});
    var out3: [8]Import.Import = undefined;
    const vv2 = try Import.findSymbol(buf, sections, "", "VerifyVersionInfoW", &out3);
    std.debug.print("VerifyVersionInfoW (any dll): {d}\n", .{vv2.len});
}

test "live termsrv.dll: memset/VerifyVersion thunks and callers (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    const Validate = @import("Validate");
    const Import = @import("Import");
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    var text_name: [8]u8 = [_]u8{0} ** 8;
    @memcpy(text_name[0..5], ".text");
    const text = Pe.findSection(sections, &text_name) orelse return error.MissingText;
    const code = buf[text.raw_ptr .. text.raw_ptr + text.raw_size];
    var out: [4]Import.Import = undefined;
    const memset = (try Import.findSymbol(buf, sections, "crt-string", "memset", &out))[0];
    const vv = (try Import.findSymbol(buf, sections, "", "VerifyVersionInfoW", &out))[0];
    var thunks: [64]Xref.Xref = undefined;
    for ([_]u32{ memset.iat_rva, vv.iat_rva }) |iat| {
        const refs = Xref.scanRipXrefs(code, text.virtual_address, iat, &thunks);
        std.debug.print("iat {x}: refs={d}\n", .{ iat, refs.len });
        for (refs) |r| {
            var callers: [256]Validate.CallTo = undefined;
            const cs = Validate.findCallsTo(code, text.virtual_address, r.at_rva, &callers);
            std.debug.print("  ref at={x} callers={d}\n", .{ r.at_rva, cs.len });
            for (cs) |c| {
                const func = Pdata.containingFunctionForRva(buf, sections, c.at_rva) catch continue;
                std.debug.print("    call at={x} func=[{x},{x})\n", .{ c.at_rva, func.begin, func.end });
            }
        }
    }
}

test "live termsrv.dll: memset x VerifyVersion caller intersection (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    const Validate = @import("Validate");
    const Import = @import("Import");
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    var text_name: [8]u8 = [_]u8{0} ** 8;
    @memcpy(text_name[0..5], ".text");
    const text = Pe.findSection(sections, &text_name) orelse return error.MissingText;
    const code = buf[text.raw_ptr .. text.raw_ptr + text.raw_size];
    var out: [4]Import.Import = undefined;
    const memset = (try Import.findSymbol(buf, sections, "crt-string", "memset", &out))[0];
    const vv = (try Import.findSymbol(buf, sections, "", "VerifyVersionInfoW", &out))[0];
    var thunks: [64]Xref.Xref = undefined;
    const mrefs = Xref.scanRipXrefs(code, text.virtual_address, memset.iat_rva, &thunks);
    try std.testing.expect(mrefs.len == 1);
    var vthunks: [64]Xref.Xref = undefined;
    const vrefs = Xref.scanRipXrefs(code, text.virtual_address, vv.iat_rva, &vthunks);
    var vcall_sites: [64]u32 = undefined;
    var nv: usize = 0;
    for (vrefs) |r| {
        const off = Pe.rvaToOffset(sections, r.at_rva) orelse continue;
        const full = Decode.decodeFull64(buf[off..][0..16]) orelse continue;
        std.debug.print("vv ref at={x} mnem={d}\n", .{ r.at_rva, full.mnemonic });
        if (full.mnemonic == Decode.CALL and nv < vcall_sites.len) {
            vcall_sites[nv] = r.at_rva;
            nv += 1;
        }
    }
    var mcallers: [512]Validate.CallTo = undefined;
    const mcs = Validate.findCallsTo(code, text.virtual_address, mrefs[0].at_rva, &mcallers);
    std.debug.print("memset callers={d} vv direct-calls={d}\n", .{ mcs.len, nv });
    for (mcs) |mc| {
        const mf = Pdata.containingFunctionForRva(buf, sections, mc.at_rva) catch continue;
        for (vcall_sites[0..nv]) |vc_at| {
            const vf = Pdata.containingFunctionForRva(buf, sections, vc_at) catch continue;
            if (mf.begin == vf.begin) {
                std.debug.print("SHARED func=[{x},{x}) memset-call={x} vv-call={x}\n", .{ mf.begin, mf.end, mc.at_rva, vc_at });
            }
        }
    }
}

test "live termsrv.dll: SingleUser candidate tails (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    std.debug.print("CALL={d} JZ={d} JNZ={d} TEST={d} CMP={d} MOV={d}\n", .{ Decode.CALL, Decode.JZ, Decode.JNZ, Decode.TEST, Decode.CMP, 505 });
    for ([_]u32{ 0x91eb2, 0x91ed5, 0xa637b }) |vc| {
        const off = Pe.rvaToOffset(sections, vc) orelse continue;
        std.debug.print("--- tail at {x} ---\n", .{vc});
        var i: usize = 0;
        var shown: usize = 0;
        while (i < 96 and shown < 14) {
            const full = Decode.decodeFull64(buf[off + i .. off + 128]) orelse {
                i += 1;
                continue;
            };
            if (full.length == 0) {
                i += 1;
                continue;
            }
            std.debug.print("  {x}: mnem={d} len={d}\n", .{ vc + @as(u32, @intCast(i)), full.mnemonic, full.length });
            i += full.length;
            shown += 1;
        }
    }
}

test "live termsrv.dll: IsSingleSessionPerUser string xrefs (read-only)" {
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
    var occ: [16]usize = undefined;
    const all = Anchors.findAllAnchors(buf, "IsSingleSessionPerUser", &occ);
    std.debug.print("IsSingleSessionPerUser occurrences={d}\n", .{all.len});
    for (all) |off| {
        const rva = Pe.offsetToRva(sections, off) orelse continue;
        var out: [256]Xref.Xref = undefined;
        const found = Xref.scanRipXrefs(code, text.virtual_address, rva, &out);
        std.debug.print("  off={x} rva={x} xrefs={d}\n", .{ off, rva, found.len });
        for (found) |x| {
            const func = Pdata.containingFunctionForRva(buf, sections, x.at_rva) catch continue;
            std.debug.print("    xref at={x} func=[{x},{x})\n", .{ x.at_rva, func.begin, func.end });
        }
    }
}

test "live termsrv.dll: SingleUser CALL-TEST-JZ site (read-only)" {
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
    const f_off = Pe.rvaToOffset(sections, 0xa62d4) orelse return error.FuncUnmapped;
    const f_end = Pe.rvaToOffset(sections, 0xa6555) orelse return error.FuncEndUnmapped;
    const site = Validate.findCallTestJz(buf[f_off..f_end], 0xa62d4) orelse return error.SiteMissing;
    std.debug.print("SingleUser site: call={x} jz={x} len={d}\n", .{ site.call_rva, site.jz_rva, site.jz_len });
    try std.testing.expect(site.jz_rva == 0xa6389);
}

test "live termsrv.dll: LocalOnly shape ranking (read-only)" {
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
    var out: [256]Validate.VersionCheckSite = undefined;
    const sites = Validate.findAllCallTestJz(buf[f_off..f_end], func_begin, &out);
    const leas = [_]u32{ 0xbbf5d, 0xbc021, 0xbc0c1, 0xbc1c7 };
    std.debug.print("call-test-jz shapes in func: {d}\n", .{sites.len});
    var shown: usize = 0;
    for (sites) |s| {
        var best: u32 = 0xFFFFFFFF;
        for (leas) |l| {
            const d: u32 = if (s.jz_rva >= l) s.jz_rva - l else l - s.jz_rva;
            if (d < best) best = d;
        }
        if (best > 1024) continue;
        const callee: u32 = 0;
        _ = callee;
        std.debug.print("  call={x} jz={x} len={d} dist-to-lea={d}\n", .{ s.call_rva, s.jz_rva, s.jz_len, best });
        shown += 1;
        if (shown >= 12) break;
    }
}

test "live termsrv.dll: top LocalOnly candidate callees (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    for ([_]u32{ 0xbbf10, 0xbc16c }) |c| {
        const off = Pe.rvaToOffset(sections, c) orelse continue;
        const full = Decode.decodeFull64(buf[off..][0..16]) orelse continue;
        std.debug.print("call at={x} ops={d}", .{ c, full.op_count });
        for (full.operands[0..full.op_count]) |op| {
            if (op.type == Decode.OP_MEM) {
                const t = Decode.ripTarget(c, full.length, op.unnamed_0.mem.disp.value);
                std.debug.print(" mem-> {x}", .{t});
            } else if (op.type == Decode.OP_IMM) {
                const t = Decode.ripTarget(c, full.length, op.unnamed_0.imm.value.s);
                std.debug.print(" rel-> {x}", .{t});
            }
        }
        std.debug.print("\n", .{});
    }
    const t_off = Pe.rvaToOffset(sections, 0x2dbac) orelse return error.X;
    std.debug.print("--- target func [2dbac,2dbc8) ---\n", .{});
    var i: usize = 0;
    while (i < 0x2dbc8 - 0x2dbac) {
        const full = Decode.decodeFull64(buf[t_off + i .. t_off + 0x20]) orelse {
            i += 1;
            continue;
        };
        if (full.length == 0) {
            i += 1;
            continue;
        }
        std.debug.print("  {x}: mnem={d} len={d}\n", .{ 0x2dbac + @as(u32, @intCast(i)), full.mnemonic, full.length });
        i += full.length;
    }
}

test "live termsrv.dll: LocalOnly heuristic top-rank (read-only)" {
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
    const f_off = Pe.rvaToOffset(sections, 0xbbea0) orelse return error.FuncUnmapped;
    const f_end = Pe.rvaToOffset(sections, 0xc24b2) orelse return error.FuncEndUnmapped;
    var shapes: [256]Validate.VersionCheckSite = undefined;
    const found = Validate.findAllCallTestJz(buf[f_off..f_end], 0xbbea0, &shapes);
    const leas = [_]u32{ 0xbbf5d, 0xbc021, 0xbc0c1, 0xbc1c7 };
    var ranked: [256]Validate.RankedSite = undefined;
    const ordered = Validate.rankByLeaProximity(found, &leas, &ranked);
    try std.testing.expect(ordered.len > 0);
    std.debug.print("LocalOnly top: jz={x} len={d} dist={d} of {d}\n", .{ ordered[0].site.jz_rva, ordered[0].site.jz_len, ordered[0].dist, ordered.len });
    try std.testing.expect(ordered[0].site.jz_rva == 0xbbf1e);
}

test "live termsrv.dll: SLInit anchor xref census (read-only)" {
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
    const markers = [_][]const u8{ "CSLQuery::Initialize", "bRemoteConnAllowed" };
    for (markers) |m| {
        var occ: [16]usize = undefined;
        const all = Anchors.findAllAnchors(buf, m, &occ);
        std.debug.print("{s}: occurrences={d}\n", .{ m, all.len });
        for (all) |off| {
            const rva = Pe.offsetToRva(sections, off) orelse continue;
            var out: [256]Xref.Xref = undefined;
            const found = Xref.scanRipXrefs(code, text.virtual_address, rva, &out);
            std.debug.print("  off={x} rva={x} xrefs={d}\n", .{ off, rva, found.len });
            for (found) |x| {
                const func = Pdata.containingFunctionForRva(buf, sections, x.at_rva) catch continue;
                std.debug.print("    xref at={x} func=[{x},{x})\n", .{ x.at_rva, func.begin, func.end });
            }
        }
    }
}

test "live termsrv.dll: MOV [RIP],1 census in CSLQuery func (read-only)" {
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
    const f_off = Pe.rvaToOffset(sections, 0xba448) orelse return error.FuncUnmapped;
    const f_end = Pe.rvaToOffset(sections, 0xbbb65) orelse return error.FuncEndUnmapped;
    var out: [64]Validate.GlobalInit = undefined;
    const inits = Validate.listMovMemImm1(buf[f_off..f_end], 0xba448, &out);
    std.debug.print("global-inits in func: {d}\n", .{inits.len});
    for (inits) |g| std.debug.print("  mov at={x} -> global {x}\n", .{ g.at_rva, g.target_rva });
}

test "live termsrv.dll: CSLQuery func callers + MOV shapes (read-only)" {
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
    var callers: [64]Validate.CallTo = undefined;
    const cs = Validate.findCallsTo(code, text.virtual_address, 0xba448, &callers);
    std.debug.print("callers of ba448: {d}\n", .{cs.len});
    for (cs) |c| {
        const func = Pdata.containingFunctionForRva(buf, sections, c.at_rva) catch continue;
        std.debug.print("  call at={x} from func=[{x},{x})\n", .{ c.at_rva, func.begin, func.end });
    }
    const f_off = Pe.rvaToOffset(sections, 0xba448) orelse return error.FuncUnmapped;
    const f_end = Pe.rvaToOffset(sections, 0xbbb65) orelse return error.FuncEndUnmapped;
    const fcode = buf[f_off..f_end];
    var i: usize = 0;
    var mov_imm: usize = 0;
    var mov_reg1: usize = 0;
    while (i < fcode.len) {
        const full = Decode.decodeFull64(fcode[i..]) orelse {
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
            if (dst.type == Decode.OP_MEM and src.type == Decode.OP_IMM) {
                mov_imm += 1;
                std.debug.print("  movmem at={x} imm={d}\n", .{ 0xba448 + @as(u32, @intCast(i)), src.unnamed_0.imm.value.u });
            }
            if (src.type == Decode.OP_IMM and src.unnamed_0.imm.value.u == 1) mov_reg1 += 1;
        }
        i += full.length;
    }
    std.debug.print("movmem-imm total={d} imm1-anydst total={d}\n", .{ mov_imm, mov_reg1 });
}

test "live termsrv.dll: discover() finds all three sites (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    const rep = try AutoFind.discover(buf);
    std.debug.print("discover: dp={?x} su={?x} lo={?x} (cands {d}/{d}/{d})\n", .{
        if (rep.def_policy) |e| e.rva else null,
        if (rep.single_user) |e| e.rva else null,
        if (rep.local_only) |e| e.rva else null,
        rep.def_policy_candidates,
        rep.single_user_candidates,
        rep.local_only_candidates,
    });
    try std.testing.expect(rep.def_policy != null);
    try std.testing.expect(rep.def_policy.?.rva == 0x6a5d0);
    try std.testing.expect(rep.single_user != null);
    try std.testing.expect(rep.single_user.?.rva == 0xa6389);
    try std.testing.expect(rep.local_only != null);
    try std.testing.expect(rep.local_only.?.rva == 0xbbf1e);
}

test "patch: applyBytes copies exact bytes, rejects host-only paths" {
    const Patch = @import("Patch");
    var dest: [8]u8 = [_]u8{0} ** 8;
    Patch.applyBytes(&dest, &[_]u8{ 0x90, 0xEB, 0x01 });
    try std.testing.expect(dest[0] == 0x90 and dest[1] == 0xEB and dest[2] == 0x01);
    try std.testing.expect(dest[3] == 0);
    try std.testing.expect(Patch.suspendOtherThreads() == error.UnsupportedOs);
    try std.testing.expect(Patch.resumeOtherThreads() == error.UnsupportedOs);
    try std.testing.expect(Patch.applyProtected(&dest, &[_]u8{0x90}) == error.UnsupportedOs);
    try std.testing.expect(Patch.hookInit() == error.UnsupportedOs);
}

test "encodeDefPolicy synthetic RCX/63C shape" {
    const Validate = @import("Validate");
    const site = Validate.CmpSite{ .at_rva = 0x1000, .disp = 0x63C, .base_reg = Decode.REG_RCX, .insn_len = 8 };
    const blob = Validate.encodeDefPolicy(site, 6) orelse return error.EncodeFailed;
    try std.testing.expect(blob.len == 14);
    const want = [_]u8{ 0xB8, 0x01, 0x00, 0x00, 0x00, 0x89, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x90, 0xEB, 0x00 };
    try std.testing.expect(std.mem.eql(u8, blob.bytes[0..14], &want));
    try std.testing.expect(Validate.encodeDefPolicy(.{ .at_rva = 0, .disp = 0x63C, .base_reg = 0xFFFFFFFF, .insn_len = 8 }, 6) == null);
    try std.testing.expect(Validate.encodeDefPolicy(site, 2) == null);
}

test "live termsrv.dll: DefPolicy blob for site 6a5c9 (read-only)" {
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
    const cmp = Validate.findCmpMemDisp(buf[f_off..f_end], 0x6a52c, 0x63C) orelse return error.CmpMissing;
    std.debug.print("cmp len={d} base={d} code={?d}\n", .{ cmp.insn_len, cmp.base_reg, Decode.regCode64(cmp.base_reg) });
    const blob = Validate.encodeDefPolicy(cmp, 6) orelse return error.EncodeFailed;
    std.debug.print("blob len={d} head={x}{x} tail={x}{x}\n", .{ blob.len, blob.bytes[0], blob.bytes[1], blob.bytes[blob.len - 2], blob.bytes[blob.len - 1] });
    try std.testing.expect(blob.len == 13);
    try std.testing.expect(blob.bytes[0] == 0x41 and blob.bytes[1] == 0xC7);
    try std.testing.expect(blob.bytes[blob.len - 2] == 0xEB and blob.bytes[blob.len - 1] == 0x00);
}

test "live termsrv.dll: SingleUser function full shape (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    const f_off = Pe.rvaToOffset(sections, 0xa62d4) orelse return error.FuncUnmapped;
    const f_end = Pe.rvaToOffset(sections, 0xa6555) orelse return error.FuncEndUnmapped;
    const code = buf[f_off..f_end];
    var i: usize = 0;
    while (i < code.len) {
        const full = Decode.decodeFull64(code[i..]) orelse {
            i += 1;
            continue;
        };
        if (full.length == 0) {
            i += 1;
            continue;
        }
        const at: u32 = 0xa62d4 + @as(u32, @intCast(i));
        if (at >= 0xa6360 and at <= 0xa6400) {
            std.debug.print("  {x}: mnem={d} len={d}\n", .{ at, full.mnemonic, full.length });
        }
        i += full.length;
    }
}

test "live termsrv.dll: SingleUser JZ polarity probe (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    for ([_]u32{ 0xa6389, 0xa638f }) |rva| {
        const off = Pe.rvaToOffset(sections, rva) orelse continue;
        const full = Decode.decodeFull64(buf[off..][0..16]) orelse continue;
        std.debug.print("at={x} len={d} ops={d}", .{ rva, full.length, full.op_count });
        for (full.operands[0..full.op_count]) |op| {
            if (op.type == Decode.OP_IMM) {
                const t = Decode.ripTarget(rva, full.length, op.unnamed_0.imm.value.s);
                std.debug.print(" imm-> {x}", .{t});
            } else if (op.type == Decode.OP_MEM) {
                std.debug.print(" mem(base={d},disp={d})", .{ op.unnamed_0.mem.base, op.unnamed_0.mem.disp.value });
            } else {
                std.debug.print(" op(type={d})", .{op.type});
            }
        }
        std.debug.print("\n", .{});
    }
}

test "live termsrv.dll: SingleUser branch targets probe (read-only)" {
    const path = "/mnt/c/Windows/System32/termsrv.dll";
    const file = std.fs.openFileAbsolute(path, .{}) catch return;
    defer file.close();
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const buf = try file.readToEndAlloc(gpa.allocator(), 8 * 1024 * 1024);
    defer gpa.allocator().free(buf);
    var secs: [16]Pe.Section = undefined;
    const sections = try Pe.parseSections(buf, &secs);
    for ([_]u32{ 0xa638f, 0xa6517 }) |rva| {
        const off = Pe.rvaToOffset(sections, rva) orelse continue;
        std.debug.print("--- path at {x} ---\n", .{rva});
        var i: usize = 0;
        var shown: usize = 0;
        while (i < 64 and shown < 8) {
            const full = Decode.decodeFull64(buf[off + i .. off + 96]) orelse {
                i += 1;
                continue;
            };
            if (full.length == 0) {
                i += 1;
                continue;
            }
            std.debug.print("  {x}: mnem={d} len={d} ops={d}\n", .{ rva + @as(u32, @intCast(i)), full.mnemonic, full.length, full.op_count });
            i += full.length;
            shown += 1;
            if (full.mnemonic == 766 or full.mnemonic == 378) break;
        }
    }
}

test "branch emitters synthetic shapes" {
    const Validate = @import("Validate");
    const nop6 = Validate.encodeNopFill(6).?;
    try std.testing.expect(std.mem.eql(u8, nop6.bytes[0..6], &[_]u8{ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }));
    try std.testing.expect(Validate.encodeNopFill(0) == null);
    try std.testing.expect(Validate.encodeNopFill(17) == null);
    const nj = Validate.encodeNopJmp(6, 0x188).?;
    try std.testing.expect(std.mem.eql(u8, nj.bytes[0..6], &[_]u8{ 0x90, 0xE9, 0x88, 0x01, 0x00, 0x00 }));
    try std.testing.expect(Validate.encodeNopJmp(4, 0) == null);
    try std.testing.expect(Validate.encodeNopJmp(6, 0x80000000) == null);
    const js = Validate.encodeJmpShort(6, 0x10).?;
    try std.testing.expect(std.mem.eql(u8, js.bytes[0..6], &[_]u8{ 0xEB, 0x10, 0x90, 0x90, 0x90, 0x90 }));
    try std.testing.expect(Validate.encodeJmpShort(6, 200) == null);
    try std.testing.expect(Validate.encodeJmpShort(1, 0) == null);
    const m1 = Validate.encodeMovEax1(7).?;
    try std.testing.expect(std.mem.eql(u8, m1.bytes[0..7], &[_]u8{ 0xB8, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90 }));
    try std.testing.expect(Validate.encodeMovEax1(4) == null);
    const z = Validate.encodeZero(3).?;
    try std.testing.expect(std.mem.eql(u8, z.bytes[0..3], &[_]u8{ 0x00, 0x00, 0x00 }));
    try std.testing.expect(Validate.encodeZero(0) == null);
}

test "live termsrv.dll: SingleUser JZ nopjmp preserves target (read-only)" {
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
    const jz_rva: u32 = 0xa6389;
    const jz_len: u8 = 6;
    const target: u32 = 0xa6517;
    const rel: i64 = @as(i64, target) - (@as(i64, jz_rva) + jz_len);
    try std.testing.expect(rel == 0x188);
    const blob = Validate.encodeNopJmp(jz_len, rel).?;
    try std.testing.expect(std.mem.eql(u8, blob.bytes[0..6], &[_]u8{ 0x90, 0xE9, 0x88, 0x01, 0x00, 0x00 }));
    _ = sections;
}

test "live termsrv.dll: LocalOnly JZ nopjmp preserves target (read-only)" {
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
    const jz_rva: u32 = 0xbbf1e;
    const off = Pe.rvaToOffset(sections, jz_rva) orelse return error.JzUnmapped;
    const full = Decode.decodeFull64(buf[off..][0..16]) orelse return error.DecodeFailed;
    try std.testing.expect((full.mnemonic == Decode.JZ or full.mnemonic == Decode.JNZ) and full.length == 6);
    var target: ?u32 = null;
    for (full.operands[0..full.op_count]) |op| {
        if (op.type != Decode.OP_IMM) continue;
        target = Decode.ripTarget(jz_rva, full.length, op.unnamed_0.imm.value.s);
    }
    const t = target orelse return error.NoTarget;
    const rel: i64 = @as(i64, t) - (@as(i64, jz_rva) + 6);
    const blob = Validate.encodeNopJmp(6, rel).?;
    try std.testing.expect(blob.bytes[0] == 0x90 and blob.bytes[1] == 0xE9);
    const back: u32 = @as(u32, blob.bytes[2]) | (@as(u32, blob.bytes[3]) << 8) | (@as(u32, blob.bytes[4]) << 16) | (@as(u32, blob.bytes[5]) << 24);
    try std.testing.expect(Decode.ripTarget(jz_rva + 1, 5, @as(i64, @bitCast(@as(u64, back)))) == t);
}
