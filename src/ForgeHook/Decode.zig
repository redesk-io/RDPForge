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
pub const JNZ: c_uint = c.ZYDIS_MNEMONIC_JNZ;
pub const TEST: c_uint = c.ZYDIS_MNEMONIC_TEST;

pub const RIP_REG: c_uint = c.ZYDIS_REGISTER_RIP;
pub const OP_MEM: c_uint = c.ZYDIS_OPERAND_TYPE_MEMORY;
pub const MAX_OPS: usize = c.ZYDIS_MAX_OPERAND_COUNT;

pub const FullInsn = struct {
    length: u8,
    mnemonic: c_uint,
    op_count: u8,
    operands: [MAX_OPS]c.ZydisDecodedOperand,
};

pub fn decodeFull64(code: []const u8) ?FullInsn {
    var decoder: c.ZydisDecoder = undefined;
    if (c.ZydisDecoderInit(&decoder, c.ZYDIS_MACHINE_MODE_LONG_64, c.ZYDIS_STACK_WIDTH_64) != c.ZYAN_STATUS_SUCCESS) return null;
    var insn: c.ZydisDecodedInstruction = undefined;
    var ops: [MAX_OPS]c.ZydisDecodedOperand = undefined;
    if (c.ZydisDecoderDecodeFull(&decoder, code.ptr, code.len, &insn, &ops) != c.ZYAN_STATUS_SUCCESS) return null;
    const n = @min(@as(usize, insn.operand_count), MAX_OPS);
    return .{
        .length = insn.length,
        .mnemonic = @bitCast(insn.mnemonic),
        .op_count = @as(u8, @intCast(n)),
        .operands = ops,
    };
}

pub fn ripTarget(insn_rva: u32, length: u8, disp: i64) u32 {
    return @as(u32, @truncate(@as(u64, @bitCast(@as(i64, insn_rva) + @as(i64, length) + disp))));
}
pub fn decode64(code: []const u8, rva: u64) ?Insn {
    var decoder: c.ZydisDecoder = undefined;
    if (c.ZydisDecoderInit(&decoder, c.ZYDIS_MACHINE_MODE_LONG_64, c.ZYDIS_STACK_WIDTH_64) != c.ZYAN_STATUS_SUCCESS) return null;
    var insn: c.ZydisDecodedInstruction = undefined;
    if (c.ZydisDecoderDecodeInstruction(&decoder, null, code.ptr, code.len, &insn) != c.ZYAN_STATUS_SUCCESS) return null;
    _ = rva;
    return .{ .length = insn.length, .mnemonic = @bitCast(insn.mnemonic) };
}
