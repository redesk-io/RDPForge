const std = @import("std");
const AutoFind = @import("AutoFind");
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
