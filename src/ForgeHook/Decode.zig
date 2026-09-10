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
pub const MOV: c_uint = c.ZYDIS_MNEMONIC_MOV;

pub const REG_RCX: c_uint = c.ZYDIS_REGISTER_RCX;

pub fn regCode64(reg: c_uint) ?u4 {
    if (reg == c.ZYDIS_REGISTER_RAX or reg == c.ZYDIS_REGISTER_EAX) return 0;
    if (reg == c.ZYDIS_REGISTER_RCX or reg == c.ZYDIS_REGISTER_ECX) return 1;
    if (reg == c.ZYDIS_REGISTER_RDX or reg == c.ZYDIS_REGISTER_EDX) return 2;
    if (reg == c.ZYDIS_REGISTER_RBX or reg == c.ZYDIS_REGISTER_EBX) return 3;
    if (reg == c.ZYDIS_REGISTER_RSP or reg == c.ZYDIS_REGISTER_ESP) return 4;
    if (reg == c.ZYDIS_REGISTER_RBP or reg == c.ZYDIS_REGISTER_EBP) return 5;
    if (reg == c.ZYDIS_REGISTER_RSI or reg == c.ZYDIS_REGISTER_ESI) return 6;
    if (reg == c.ZYDIS_REGISTER_RDI or reg == c.ZYDIS_REGISTER_EDI) return 7;
    if (reg == c.ZYDIS_REGISTER_R8 or reg == c.ZYDIS_REGISTER_R8D) return 8;
    if (reg == c.ZYDIS_REGISTER_R9 or reg == c.ZYDIS_REGISTER_R9D) return 9;
    if (reg == c.ZYDIS_REGISTER_R10 or reg == c.ZYDIS_REGISTER_R10D) return 10;
    if (reg == c.ZYDIS_REGISTER_R11 or reg == c.ZYDIS_REGISTER_R11D) return 11;
    if (reg == c.ZYDIS_REGISTER_R12 or reg == c.ZYDIS_REGISTER_R12D) return 12;
    if (reg == c.ZYDIS_REGISTER_R13 or reg == c.ZYDIS_REGISTER_R13D) return 13;
    if (reg == c.ZYDIS_REGISTER_R14 or reg == c.ZYDIS_REGISTER_R14D) return 14;
    if (reg == c.ZYDIS_REGISTER_R15 or reg == c.ZYDIS_REGISTER_R15D) return 15;
    return null;
}

pub const RIP_REG: c_uint = c.ZYDIS_REGISTER_RIP;
pub const OP_MEM: c_uint = c.ZYDIS_OPERAND_TYPE_MEMORY;
pub const OP_IMM: c_uint = c.ZYDIS_OPERAND_TYPE_IMMEDIATE;
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
