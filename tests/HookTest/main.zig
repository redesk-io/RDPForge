const std = @import("std");
const AutoFind = @import("AutoFind");
const Pe = @import("Pe");
const Anchors = @import("Anchors");
const Decode = @import("Decode");

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
