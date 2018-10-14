module capstone.xcore;

extern (C):

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014-2015 */

/// Operand type for instruction's operands
enum xcore_op_type
{
    XCORE_OP_INVALID = 0, ///< = CS_OP_INVALID (Uninitialized).
    XCORE_OP_REG = 1, ///< = CS_OP_REG (Register operand).
    XCORE_OP_IMM = 2, ///< = CS_OP_IMM (Immediate operand).
    XCORE_OP_MEM = 3 ///< = CS_OP_MEM (Memory operand).
}

/// XCore registers
enum xcore_reg
{
    XCORE_REG_INVALID = 0,

    XCORE_REG_CP = 1,
    XCORE_REG_DP = 2,
    XCORE_REG_LR = 3,
    XCORE_REG_SP = 4,
    XCORE_REG_R0 = 5,
    XCORE_REG_R1 = 6,
    XCORE_REG_R2 = 7,
    XCORE_REG_R3 = 8,
    XCORE_REG_R4 = 9,
    XCORE_REG_R5 = 10,
    XCORE_REG_R6 = 11,
    XCORE_REG_R7 = 12,
    XCORE_REG_R8 = 13,
    XCORE_REG_R9 = 14,
    XCORE_REG_R10 = 15,
    XCORE_REG_R11 = 16,

    // pseudo registers
    XCORE_REG_PC = 17, ///< pc

    // internal thread registers
    // see The-XMOS-XS1-Architecture(X7879A).pdf
    XCORE_REG_SCP = 18, ///< save pc
    XCORE_REG_SSR = 19, //< save status
    XCORE_REG_ET = 20, //< exception type
    XCORE_REG_ED = 21, //< exception data
    XCORE_REG_SED = 22, //< save exception data
    XCORE_REG_KEP = 23, //< kernel entry pointer
    XCORE_REG_KSP = 24, //< kernel stack pointer
    XCORE_REG_ID = 25, //< thread ID

    XCORE_REG_ENDING = 26 // <-- mark the end of the list of registers
}

/// Instruction's operand referring to memory
/// This is associated with XCORE_OP_MEM operand type above
struct xcore_op_mem
{
    ubyte base; ///< base register, can be safely interpreted as
    ///< a value of type `xcore_reg`, but it is only
    ///< one byte wide
    ubyte index; ///< index register, same conditions apply here
    int disp; ///< displacement/offset value
    int direct; ///< +1: forward, -1: backward
}

/// Instruction operand
struct cs_xcore_op
{
    xcore_op_type type; ///< operand type
    union
    {
        xcore_reg reg; ///< register value for REG operand
        int imm; ///< immediate value for IMM operand
        xcore_op_mem mem; ///< base/disp value for MEM operand
    }
}

/// Instruction structure
struct cs_xcore
{
    /// Number of operands of this instruction,
    /// or 0 when instruction has no operand.
    ubyte op_count;
    cs_xcore_op[8] operands; ///< operands for this instruction.
}

/// XCore instruction
enum xcore_insn
{
    XCORE_INS_INVALID = 0,

    XCORE_INS_ADD = 1,
    XCORE_INS_ANDNOT = 2,
    XCORE_INS_AND = 3,
    XCORE_INS_ASHR = 4,
    XCORE_INS_BAU = 5,
    XCORE_INS_BITREV = 6,
    XCORE_INS_BLA = 7,
    XCORE_INS_BLAT = 8,
    XCORE_INS_BL = 9,
    XCORE_INS_BF = 10,
    XCORE_INS_BT = 11,
    XCORE_INS_BU = 12,
    XCORE_INS_BRU = 13,
    XCORE_INS_BYTEREV = 14,
    XCORE_INS_CHKCT = 15,
    XCORE_INS_CLRE = 16,
    XCORE_INS_CLRPT = 17,
    XCORE_INS_CLRSR = 18,
    XCORE_INS_CLZ = 19,
    XCORE_INS_CRC8 = 20,
    XCORE_INS_CRC32 = 21,
    XCORE_INS_DCALL = 22,
    XCORE_INS_DENTSP = 23,
    XCORE_INS_DGETREG = 24,
    XCORE_INS_DIVS = 25,
    XCORE_INS_DIVU = 26,
    XCORE_INS_DRESTSP = 27,
    XCORE_INS_DRET = 28,
    XCORE_INS_ECALLF = 29,
    XCORE_INS_ECALLT = 30,
    XCORE_INS_EDU = 31,
    XCORE_INS_EEF = 32,
    XCORE_INS_EET = 33,
    XCORE_INS_EEU = 34,
    XCORE_INS_ENDIN = 35,
    XCORE_INS_ENTSP = 36,
    XCORE_INS_EQ = 37,
    XCORE_INS_EXTDP = 38,
    XCORE_INS_EXTSP = 39,
    XCORE_INS_FREER = 40,
    XCORE_INS_FREET = 41,
    XCORE_INS_GETD = 42,
    XCORE_INS_GET = 43,
    XCORE_INS_GETN = 44,
    XCORE_INS_GETR = 45,
    XCORE_INS_GETSR = 46,
    XCORE_INS_GETST = 47,
    XCORE_INS_GETTS = 48,
    XCORE_INS_INCT = 49,
    XCORE_INS_INIT = 50,
    XCORE_INS_INPW = 51,
    XCORE_INS_INSHR = 52,
    XCORE_INS_INT = 53,
    XCORE_INS_IN = 54,
    XCORE_INS_KCALL = 55,
    XCORE_INS_KENTSP = 56,
    XCORE_INS_KRESTSP = 57,
    XCORE_INS_KRET = 58,
    XCORE_INS_LADD = 59,
    XCORE_INS_LD16S = 60,
    XCORE_INS_LD8U = 61,
    XCORE_INS_LDA16 = 62,
    XCORE_INS_LDAP = 63,
    XCORE_INS_LDAW = 64,
    XCORE_INS_LDC = 65,
    XCORE_INS_LDW = 66,
    XCORE_INS_LDIVU = 67,
    XCORE_INS_LMUL = 68,
    XCORE_INS_LSS = 69,
    XCORE_INS_LSUB = 70,
    XCORE_INS_LSU = 71,
    XCORE_INS_MACCS = 72,
    XCORE_INS_MACCU = 73,
    XCORE_INS_MJOIN = 74,
    XCORE_INS_MKMSK = 75,
    XCORE_INS_MSYNC = 76,
    XCORE_INS_MUL = 77,
    XCORE_INS_NEG = 78,
    XCORE_INS_NOT = 79,
    XCORE_INS_OR = 80,
    XCORE_INS_OUTCT = 81,
    XCORE_INS_OUTPW = 82,
    XCORE_INS_OUTSHR = 83,
    XCORE_INS_OUTT = 84,
    XCORE_INS_OUT = 85,
    XCORE_INS_PEEK = 86,
    XCORE_INS_REMS = 87,
    XCORE_INS_REMU = 88,
    XCORE_INS_RETSP = 89,
    XCORE_INS_SETCLK = 90,
    XCORE_INS_SET = 91,
    XCORE_INS_SETC = 92,
    XCORE_INS_SETD = 93,
    XCORE_INS_SETEV = 94,
    XCORE_INS_SETN = 95,
    XCORE_INS_SETPSC = 96,
    XCORE_INS_SETPT = 97,
    XCORE_INS_SETRDY = 98,
    XCORE_INS_SETSR = 99,
    XCORE_INS_SETTW = 100,
    XCORE_INS_SETV = 101,
    XCORE_INS_SEXT = 102,
    XCORE_INS_SHL = 103,
    XCORE_INS_SHR = 104,
    XCORE_INS_SSYNC = 105,
    XCORE_INS_ST16 = 106,
    XCORE_INS_ST8 = 107,
    XCORE_INS_STW = 108,
    XCORE_INS_SUB = 109,
    XCORE_INS_SYNCR = 110,
    XCORE_INS_TESTCT = 111,
    XCORE_INS_TESTLCL = 112,
    XCORE_INS_TESTWCT = 113,
    XCORE_INS_TSETMR = 114,
    XCORE_INS_START = 115,
    XCORE_INS_WAITEF = 116,
    XCORE_INS_WAITET = 117,
    XCORE_INS_WAITEU = 118,
    XCORE_INS_XOR = 119,
    XCORE_INS_ZEXT = 120,

    XCORE_INS_ENDING = 121 // <-- mark the end of the list of instructions
}

/// Group of XCore instructions
enum xcore_insn_group
{
    XCORE_GRP_INVALID = 0, ///< = CS_GRP_INVALID

    // Generic groups
    // all jump instructions (conditional+direct+indirect jumps)
    XCORE_GRP_JUMP = 1, ///< = CS_GRP_JUMP

    XCORE_GRP_ENDING = 2 // <-- mark the end of the list of groups
}
