const c = @cImport({
    @cInclude("Zydis/Zydis.h");
});

pub const DecodeError = error{BadModeInit};

pub const Insn = struct {
    length: u8,
    mnemonic: c_uint,
};

pub const LEA: c_uint = c.ZYDIS_MNEMONIC_LEA;
pub const CALL: c_uint = c.ZYDIS_MNEMONIC_CALL;
pub const CMP: c_uint = c.ZYDIS_MNEMONIC_CMP;
pub const JZ: c_uint = c.ZYDIS_MNEMONIC_JZ;
pub const TEST: c_uint = c.ZYDIS_MNEMONIC_TEST;

pub fn decode64(code: []const u8, rva: u64) ?Insn {
    var decoder: c.ZydisDecoder = undefined;
    if (c.ZydisDecoderInit(&decoder, c.ZYDIS_MACHINE_MODE_LONG_64, c.ZYDIS_STACK_WIDTH_64) != c.ZYAN_STATUS_SUCCESS) return null;
    var insn: c.ZydisDecodedInstruction = undefined;
    if (c.ZydisDecoderDecodeInstruction(&decoder, null, code.ptr, code.len, &insn) != c.ZYAN_STATUS_SUCCESS) return null;
    _ = rva;
    return .{ .length = insn.length, .mnemonic = @bitCast(insn.mnemonic) };
}
