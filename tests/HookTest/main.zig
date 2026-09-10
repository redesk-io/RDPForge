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
