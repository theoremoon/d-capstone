module capstone.ppc;

extern (C):

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

/// PPC branch codes for some branch instructions
enum ppc_bc
{
    PPC_BC_INVALID = 0,
    PPC_BC_LT = (0 << 5) | 12,
    PPC_BC_LE = (1 << 5) | 4,
    PPC_BC_EQ = (2 << 5) | 12,
    PPC_BC_GE = (0 << 5) | 4,
    PPC_BC_GT = (1 << 5) | 12,
    PPC_BC_NE = (2 << 5) | 4,
    PPC_BC_UN = (3 << 5) | 12,
    PPC_BC_NU = (3 << 5) | 4,

    // extra conditions
    PPC_BC_SO = (4 << 5) | 12, ///< summary overflow
    PPC_BC_NS = (4 << 5) | 4 ///< not summary overflow
}

/// PPC branch hint for some branch instructions
enum ppc_bh
{
    PPC_BH_INVALID = 0, ///< no hint
    PPC_BH_PLUS = 1, ///< PLUS hint
    PPC_BH_MINUS = 2 ///< MINUS hint
}

/// Operand type for instruction's operands
enum ppc_op_type
{
    PPC_OP_INVALID = 0, ///< = CS_OP_INVALID (Uninitialized).
    PPC_OP_REG = 1, ///< = CS_OP_REG (Register operand).
    PPC_OP_IMM = 2, ///< = CS_OP_IMM (Immediate operand).
    PPC_OP_MEM = 3, ///< = CS_OP_MEM (Memory operand).
    PPC_OP_CRX = 64 ///< Condition Register field
}

/// PPC registers
enum ppc_reg
{
    PPC_REG_INVALID = 0,

    PPC_REG_CARRY = 1,
    PPC_REG_CR0 = 2,
    PPC_REG_CR1 = 3,
    PPC_REG_CR2 = 4,
    PPC_REG_CR3 = 5,
    PPC_REG_CR4 = 6,
    PPC_REG_CR5 = 7,
    PPC_REG_CR6 = 8,
    PPC_REG_CR7 = 9,
    PPC_REG_CTR = 10,
    PPC_REG_F0 = 11,
    PPC_REG_F1 = 12,
    PPC_REG_F2 = 13,
    PPC_REG_F3 = 14,
    PPC_REG_F4 = 15,
    PPC_REG_F5 = 16,
    PPC_REG_F6 = 17,
    PPC_REG_F7 = 18,
    PPC_REG_F8 = 19,
    PPC_REG_F9 = 20,
    PPC_REG_F10 = 21,
    PPC_REG_F11 = 22,
    PPC_REG_F12 = 23,
    PPC_REG_F13 = 24,
    PPC_REG_F14 = 25,
    PPC_REG_F15 = 26,
    PPC_REG_F16 = 27,
    PPC_REG_F17 = 28,
    PPC_REG_F18 = 29,
    PPC_REG_F19 = 30,
    PPC_REG_F20 = 31,
    PPC_REG_F21 = 32,
    PPC_REG_F22 = 33,
    PPC_REG_F23 = 34,
    PPC_REG_F24 = 35,
    PPC_REG_F25 = 36,
    PPC_REG_F26 = 37,
    PPC_REG_F27 = 38,
    PPC_REG_F28 = 39,
    PPC_REG_F29 = 40,
    PPC_REG_F30 = 41,
    PPC_REG_F31 = 42,
    PPC_REG_LR = 43,
    PPC_REG_R0 = 44,
    PPC_REG_R1 = 45,
    PPC_REG_R2 = 46,
    PPC_REG_R3 = 47,
    PPC_REG_R4 = 48,
    PPC_REG_R5 = 49,
    PPC_REG_R6 = 50,
    PPC_REG_R7 = 51,
    PPC_REG_R8 = 52,
    PPC_REG_R9 = 53,
    PPC_REG_R10 = 54,
    PPC_REG_R11 = 55,
    PPC_REG_R12 = 56,
    PPC_REG_R13 = 57,
    PPC_REG_R14 = 58,
    PPC_REG_R15 = 59,
    PPC_REG_R16 = 60,
    PPC_REG_R17 = 61,
    PPC_REG_R18 = 62,
    PPC_REG_R19 = 63,
    PPC_REG_R20 = 64,
    PPC_REG_R21 = 65,
    PPC_REG_R22 = 66,
    PPC_REG_R23 = 67,
    PPC_REG_R24 = 68,
    PPC_REG_R25 = 69,
    PPC_REG_R26 = 70,
    PPC_REG_R27 = 71,
    PPC_REG_R28 = 72,
    PPC_REG_R29 = 73,
    PPC_REG_R30 = 74,
    PPC_REG_R31 = 75,
    PPC_REG_V0 = 76,
    PPC_REG_V1 = 77,
    PPC_REG_V2 = 78,
    PPC_REG_V3 = 79,
    PPC_REG_V4 = 80,
    PPC_REG_V5 = 81,
    PPC_REG_V6 = 82,
    PPC_REG_V7 = 83,
    PPC_REG_V8 = 84,
    PPC_REG_V9 = 85,
    PPC_REG_V10 = 86,
    PPC_REG_V11 = 87,
    PPC_REG_V12 = 88,
    PPC_REG_V13 = 89,
    PPC_REG_V14 = 90,
    PPC_REG_V15 = 91,
    PPC_REG_V16 = 92,
    PPC_REG_V17 = 93,
    PPC_REG_V18 = 94,
    PPC_REG_V19 = 95,
    PPC_REG_V20 = 96,
    PPC_REG_V21 = 97,
    PPC_REG_V22 = 98,
    PPC_REG_V23 = 99,
    PPC_REG_V24 = 100,
    PPC_REG_V25 = 101,
    PPC_REG_V26 = 102,
    PPC_REG_V27 = 103,
    PPC_REG_V28 = 104,
    PPC_REG_V29 = 105,
    PPC_REG_V30 = 106,
    PPC_REG_V31 = 107,
    PPC_REG_VRSAVE = 108,
    PPC_REG_VS0 = 109,
    PPC_REG_VS1 = 110,
    PPC_REG_VS2 = 111,
    PPC_REG_VS3 = 112,
    PPC_REG_VS4 = 113,
    PPC_REG_VS5 = 114,
    PPC_REG_VS6 = 115,
    PPC_REG_VS7 = 116,
    PPC_REG_VS8 = 117,
    PPC_REG_VS9 = 118,
    PPC_REG_VS10 = 119,
    PPC_REG_VS11 = 120,
    PPC_REG_VS12 = 121,
    PPC_REG_VS13 = 122,
    PPC_REG_VS14 = 123,
    PPC_REG_VS15 = 124,
    PPC_REG_VS16 = 125,
    PPC_REG_VS17 = 126,
    PPC_REG_VS18 = 127,
    PPC_REG_VS19 = 128,
    PPC_REG_VS20 = 129,
    PPC_REG_VS21 = 130,
    PPC_REG_VS22 = 131,
    PPC_REG_VS23 = 132,
    PPC_REG_VS24 = 133,
    PPC_REG_VS25 = 134,
    PPC_REG_VS26 = 135,
    PPC_REG_VS27 = 136,
    PPC_REG_VS28 = 137,
    PPC_REG_VS29 = 138,
    PPC_REG_VS30 = 139,
    PPC_REG_VS31 = 140,
    PPC_REG_VS32 = 141,
    PPC_REG_VS33 = 142,
    PPC_REG_VS34 = 143,
    PPC_REG_VS35 = 144,
    PPC_REG_VS36 = 145,
    PPC_REG_VS37 = 146,
    PPC_REG_VS38 = 147,
    PPC_REG_VS39 = 148,
    PPC_REG_VS40 = 149,
    PPC_REG_VS41 = 150,
    PPC_REG_VS42 = 151,
    PPC_REG_VS43 = 152,
    PPC_REG_VS44 = 153,
    PPC_REG_VS45 = 154,
    PPC_REG_VS46 = 155,
    PPC_REG_VS47 = 156,
    PPC_REG_VS48 = 157,
    PPC_REG_VS49 = 158,
    PPC_REG_VS50 = 159,
    PPC_REG_VS51 = 160,
    PPC_REG_VS52 = 161,
    PPC_REG_VS53 = 162,
    PPC_REG_VS54 = 163,
    PPC_REG_VS55 = 164,
    PPC_REG_VS56 = 165,
    PPC_REG_VS57 = 166,
    PPC_REG_VS58 = 167,
    PPC_REG_VS59 = 168,
    PPC_REG_VS60 = 169,
    PPC_REG_VS61 = 170,
    PPC_REG_VS62 = 171,
    PPC_REG_VS63 = 172,
    PPC_REG_Q0 = 173,
    PPC_REG_Q1 = 174,
    PPC_REG_Q2 = 175,
    PPC_REG_Q3 = 176,
    PPC_REG_Q4 = 177,
    PPC_REG_Q5 = 178,
    PPC_REG_Q6 = 179,
    PPC_REG_Q7 = 180,
    PPC_REG_Q8 = 181,
    PPC_REG_Q9 = 182,
    PPC_REG_Q10 = 183,
    PPC_REG_Q11 = 184,
    PPC_REG_Q12 = 185,
    PPC_REG_Q13 = 186,
    PPC_REG_Q14 = 187,
    PPC_REG_Q15 = 188,
    PPC_REG_Q16 = 189,
    PPC_REG_Q17 = 190,
    PPC_REG_Q18 = 191,
    PPC_REG_Q19 = 192,
    PPC_REG_Q20 = 193,
    PPC_REG_Q21 = 194,
    PPC_REG_Q22 = 195,
    PPC_REG_Q23 = 196,
    PPC_REG_Q24 = 197,
    PPC_REG_Q25 = 198,
    PPC_REG_Q26 = 199,
    PPC_REG_Q27 = 200,
    PPC_REG_Q28 = 201,
    PPC_REG_Q29 = 202,
    PPC_REG_Q30 = 203,
    PPC_REG_Q31 = 204,

    // extra registers for PPCMapping.c
    PPC_REG_RM = 205,
    PPC_REG_CTR8 = 206,
    PPC_REG_LR8 = 207,
    PPC_REG_CR1EQ = 208,
    PPC_REG_X2 = 209,

    PPC_REG_ENDING = 210 // <-- mark the end of the list of registers
}

/// Instruction's operand referring to memory
/// This is associated with PPC_OP_MEM operand type above
struct ppc_op_mem
{
    ppc_reg base; ///< base register
    int disp; ///< displacement/offset value
}

struct ppc_op_crx
{
    uint scale;
    ppc_reg reg;
    ppc_bc cond;
}

/// Instruction operand
struct cs_ppc_op
{
    ppc_op_type type; ///< operand type
    union
    {
        ppc_reg reg; ///< register value for REG operand
        long imm; ///< immediate value for IMM operand
        ppc_op_mem mem; ///< base/disp value for MEM operand
        ppc_op_crx crx; ///< operand with condition register
    }
}

/// Instruction structure
struct cs_ppc
{
    /// branch code for branch instructions
    ppc_bc bc;

    /// branch hint for branch instructions
    ppc_bh bh;

    /// if update_cr0 = True, then this 'dot' insn updates CR0
    bool update_cr0;

    /// Number of operands of this instruction,
    /// or 0 when instruction has no operand.
    ubyte op_count;
    cs_ppc_op[8] operands; ///< operands for this instruction.
}

/// PPC instruction
enum ppc_insn
{
    PPC_INS_INVALID = 0,

    PPC_INS_ADD = 1,
    PPC_INS_ADDC = 2,
    PPC_INS_ADDE = 3,
    PPC_INS_ADDI = 4,
    PPC_INS_ADDIC = 5,
    PPC_INS_ADDIS = 6,
    PPC_INS_ADDME = 7,
    PPC_INS_ADDZE = 8,
    PPC_INS_AND = 9,
    PPC_INS_ANDC = 10,
    PPC_INS_ANDIS = 11,
    PPC_INS_ANDI = 12,
    PPC_INS_ATTN = 13,
    PPC_INS_B = 14,
    PPC_INS_BA = 15,
    PPC_INS_BC = 16,
    PPC_INS_BCCTR = 17,
    PPC_INS_BCCTRL = 18,
    PPC_INS_BCL = 19,
    PPC_INS_BCLR = 20,
    PPC_INS_BCLRL = 21,
    PPC_INS_BCTR = 22,
    PPC_INS_BCTRL = 23,
    PPC_INS_BCT = 24,
    PPC_INS_BDNZ = 25,
    PPC_INS_BDNZA = 26,
    PPC_INS_BDNZL = 27,
    PPC_INS_BDNZLA = 28,
    PPC_INS_BDNZLR = 29,
    PPC_INS_BDNZLRL = 30,
    PPC_INS_BDZ = 31,
    PPC_INS_BDZA = 32,
    PPC_INS_BDZL = 33,
    PPC_INS_BDZLA = 34,
    PPC_INS_BDZLR = 35,
    PPC_INS_BDZLRL = 36,
    PPC_INS_BL = 37,
    PPC_INS_BLA = 38,
    PPC_INS_BLR = 39,
    PPC_INS_BLRL = 40,
    PPC_INS_BRINC = 41,
    PPC_INS_CMPB = 42,
    PPC_INS_CMPD = 43,
    PPC_INS_CMPDI = 44,
    PPC_INS_CMPLD = 45,
    PPC_INS_CMPLDI = 46,
    PPC_INS_CMPLW = 47,
    PPC_INS_CMPLWI = 48,
    PPC_INS_CMPW = 49,
    PPC_INS_CMPWI = 50,
    PPC_INS_CNTLZD = 51,
    PPC_INS_CNTLZW = 52,
    PPC_INS_CREQV = 53,
    PPC_INS_CRXOR = 54,
    PPC_INS_CRAND = 55,
    PPC_INS_CRANDC = 56,
    PPC_INS_CRNAND = 57,
    PPC_INS_CRNOR = 58,
    PPC_INS_CROR = 59,
    PPC_INS_CRORC = 60,
    PPC_INS_DCBA = 61,
    PPC_INS_DCBF = 62,
    PPC_INS_DCBI = 63,
    PPC_INS_DCBST = 64,
    PPC_INS_DCBT = 65,
    PPC_INS_DCBTST = 66,
    PPC_INS_DCBZ = 67,
    PPC_INS_DCBZL = 68,
    PPC_INS_DCCCI = 69,
    PPC_INS_DIVD = 70,
    PPC_INS_DIVDU = 71,
    PPC_INS_DIVW = 72,
    PPC_INS_DIVWU = 73,
    PPC_INS_DSS = 74,
    PPC_INS_DSSALL = 75,
    PPC_INS_DST = 76,
    PPC_INS_DSTST = 77,
    PPC_INS_DSTSTT = 78,
    PPC_INS_DSTT = 79,
    PPC_INS_EQV = 80,
    PPC_INS_EVABS = 81,
    PPC_INS_EVADDIW = 82,
    PPC_INS_EVADDSMIAAW = 83,
    PPC_INS_EVADDSSIAAW = 84,
    PPC_INS_EVADDUMIAAW = 85,
    PPC_INS_EVADDUSIAAW = 86,
    PPC_INS_EVADDW = 87,
    PPC_INS_EVAND = 88,
    PPC_INS_EVANDC = 89,
    PPC_INS_EVCMPEQ = 90,
    PPC_INS_EVCMPGTS = 91,
    PPC_INS_EVCMPGTU = 92,
    PPC_INS_EVCMPLTS = 93,
    PPC_INS_EVCMPLTU = 94,
    PPC_INS_EVCNTLSW = 95,
    PPC_INS_EVCNTLZW = 96,
    PPC_INS_EVDIVWS = 97,
    PPC_INS_EVDIVWU = 98,
    PPC_INS_EVEQV = 99,
    PPC_INS_EVEXTSB = 100,
    PPC_INS_EVEXTSH = 101,
    PPC_INS_EVLDD = 102,
    PPC_INS_EVLDDX = 103,
    PPC_INS_EVLDH = 104,
    PPC_INS_EVLDHX = 105,
    PPC_INS_EVLDW = 106,
    PPC_INS_EVLDWX = 107,
    PPC_INS_EVLHHESPLAT = 108,
    PPC_INS_EVLHHESPLATX = 109,
    PPC_INS_EVLHHOSSPLAT = 110,
    PPC_INS_EVLHHOSSPLATX = 111,
    PPC_INS_EVLHHOUSPLAT = 112,
    PPC_INS_EVLHHOUSPLATX = 113,
    PPC_INS_EVLWHE = 114,
    PPC_INS_EVLWHEX = 115,
    PPC_INS_EVLWHOS = 116,
    PPC_INS_EVLWHOSX = 117,
    PPC_INS_EVLWHOU = 118,
    PPC_INS_EVLWHOUX = 119,
    PPC_INS_EVLWHSPLAT = 120,
    PPC_INS_EVLWHSPLATX = 121,
    PPC_INS_EVLWWSPLAT = 122,
    PPC_INS_EVLWWSPLATX = 123,
    PPC_INS_EVMERGEHI = 124,
    PPC_INS_EVMERGEHILO = 125,
    PPC_INS_EVMERGELO = 126,
    PPC_INS_EVMERGELOHI = 127,
    PPC_INS_EVMHEGSMFAA = 128,
    PPC_INS_EVMHEGSMFAN = 129,
    PPC_INS_EVMHEGSMIAA = 130,
    PPC_INS_EVMHEGSMIAN = 131,
    PPC_INS_EVMHEGUMIAA = 132,
    PPC_INS_EVMHEGUMIAN = 133,
    PPC_INS_EVMHESMF = 134,
    PPC_INS_EVMHESMFA = 135,
    PPC_INS_EVMHESMFAAW = 136,
    PPC_INS_EVMHESMFANW = 137,
    PPC_INS_EVMHESMI = 138,
    PPC_INS_EVMHESMIA = 139,
    PPC_INS_EVMHESMIAAW = 140,
    PPC_INS_EVMHESMIANW = 141,
    PPC_INS_EVMHESSF = 142,
    PPC_INS_EVMHESSFA = 143,
    PPC_INS_EVMHESSFAAW = 144,
    PPC_INS_EVMHESSFANW = 145,
    PPC_INS_EVMHESSIAAW = 146,
    PPC_INS_EVMHESSIANW = 147,
    PPC_INS_EVMHEUMI = 148,
    PPC_INS_EVMHEUMIA = 149,
    PPC_INS_EVMHEUMIAAW = 150,
    PPC_INS_EVMHEUMIANW = 151,
    PPC_INS_EVMHEUSIAAW = 152,
    PPC_INS_EVMHEUSIANW = 153,
    PPC_INS_EVMHOGSMFAA = 154,
    PPC_INS_EVMHOGSMFAN = 155,
    PPC_INS_EVMHOGSMIAA = 156,
    PPC_INS_EVMHOGSMIAN = 157,
    PPC_INS_EVMHOGUMIAA = 158,
    PPC_INS_EVMHOGUMIAN = 159,
    PPC_INS_EVMHOSMF = 160,
    PPC_INS_EVMHOSMFA = 161,
    PPC_INS_EVMHOSMFAAW = 162,
    PPC_INS_EVMHOSMFANW = 163,
    PPC_INS_EVMHOSMI = 164,
    PPC_INS_EVMHOSMIA = 165,
    PPC_INS_EVMHOSMIAAW = 166,
    PPC_INS_EVMHOSMIANW = 167,
    PPC_INS_EVMHOSSF = 168,
    PPC_INS_EVMHOSSFA = 169,
    PPC_INS_EVMHOSSFAAW = 170,
    PPC_INS_EVMHOSSFANW = 171,
    PPC_INS_EVMHOSSIAAW = 172,
    PPC_INS_EVMHOSSIANW = 173,
    PPC_INS_EVMHOUMI = 174,
    PPC_INS_EVMHOUMIA = 175,
    PPC_INS_EVMHOUMIAAW = 176,
    PPC_INS_EVMHOUMIANW = 177,
    PPC_INS_EVMHOUSIAAW = 178,
    PPC_INS_EVMHOUSIANW = 179,
    PPC_INS_EVMRA = 180,
    PPC_INS_EVMWHSMF = 181,
    PPC_INS_EVMWHSMFA = 182,
    PPC_INS_EVMWHSMI = 183,
    PPC_INS_EVMWHSMIA = 184,
    PPC_INS_EVMWHSSF = 185,
    PPC_INS_EVMWHSSFA = 186,
    PPC_INS_EVMWHUMI = 187,
    PPC_INS_EVMWHUMIA = 188,
    PPC_INS_EVMWLSMIAAW = 189,
    PPC_INS_EVMWLSMIANW = 190,
    PPC_INS_EVMWLSSIAAW = 191,
    PPC_INS_EVMWLSSIANW = 192,
    PPC_INS_EVMWLUMI = 193,
    PPC_INS_EVMWLUMIA = 194,
    PPC_INS_EVMWLUMIAAW = 195,
    PPC_INS_EVMWLUMIANW = 196,
    PPC_INS_EVMWLUSIAAW = 197,
    PPC_INS_EVMWLUSIANW = 198,
    PPC_INS_EVMWSMF = 199,
    PPC_INS_EVMWSMFA = 200,
    PPC_INS_EVMWSMFAA = 201,
    PPC_INS_EVMWSMFAN = 202,
    PPC_INS_EVMWSMI = 203,
    PPC_INS_EVMWSMIA = 204,
    PPC_INS_EVMWSMIAA = 205,
    PPC_INS_EVMWSMIAN = 206,
    PPC_INS_EVMWSSF = 207,
    PPC_INS_EVMWSSFA = 208,
    PPC_INS_EVMWSSFAA = 209,
    PPC_INS_EVMWSSFAN = 210,
    PPC_INS_EVMWUMI = 211,
    PPC_INS_EVMWUMIA = 212,
    PPC_INS_EVMWUMIAA = 213,
    PPC_INS_EVMWUMIAN = 214,
    PPC_INS_EVNAND = 215,
    PPC_INS_EVNEG = 216,
    PPC_INS_EVNOR = 217,
    PPC_INS_EVOR = 218,
    PPC_INS_EVORC = 219,
    PPC_INS_EVRLW = 220,
    PPC_INS_EVRLWI = 221,
    PPC_INS_EVRNDW = 222,
    PPC_INS_EVSLW = 223,
    PPC_INS_EVSLWI = 224,
    PPC_INS_EVSPLATFI = 225,
    PPC_INS_EVSPLATI = 226,
    PPC_INS_EVSRWIS = 227,
    PPC_INS_EVSRWIU = 228,
    PPC_INS_EVSRWS = 229,
    PPC_INS_EVSRWU = 230,
    PPC_INS_EVSTDD = 231,
    PPC_INS_EVSTDDX = 232,
    PPC_INS_EVSTDH = 233,
    PPC_INS_EVSTDHX = 234,
    PPC_INS_EVSTDW = 235,
    PPC_INS_EVSTDWX = 236,
    PPC_INS_EVSTWHE = 237,
    PPC_INS_EVSTWHEX = 238,
    PPC_INS_EVSTWHO = 239,
    PPC_INS_EVSTWHOX = 240,
    PPC_INS_EVSTWWE = 241,
    PPC_INS_EVSTWWEX = 242,
    PPC_INS_EVSTWWO = 243,
    PPC_INS_EVSTWWOX = 244,
    PPC_INS_EVSUBFSMIAAW = 245,
    PPC_INS_EVSUBFSSIAAW = 246,
    PPC_INS_EVSUBFUMIAAW = 247,
    PPC_INS_EVSUBFUSIAAW = 248,
    PPC_INS_EVSUBFW = 249,
    PPC_INS_EVSUBIFW = 250,
    PPC_INS_EVXOR = 251,
    PPC_INS_EXTSB = 252,
    PPC_INS_EXTSH = 253,
    PPC_INS_EXTSW = 254,
    PPC_INS_EIEIO = 255,
    PPC_INS_FABS = 256,
    PPC_INS_FADD = 257,
    PPC_INS_FADDS = 258,
    PPC_INS_FCFID = 259,
    PPC_INS_FCFIDS = 260,
    PPC_INS_FCFIDU = 261,
    PPC_INS_FCFIDUS = 262,
    PPC_INS_FCMPU = 263,
    PPC_INS_FCPSGN = 264,
    PPC_INS_FCTID = 265,
    PPC_INS_FCTIDUZ = 266,
    PPC_INS_FCTIDZ = 267,
    PPC_INS_FCTIW = 268,
    PPC_INS_FCTIWUZ = 269,
    PPC_INS_FCTIWZ = 270,
    PPC_INS_FDIV = 271,
    PPC_INS_FDIVS = 272,
    PPC_INS_FMADD = 273,
    PPC_INS_FMADDS = 274,
    PPC_INS_FMR = 275,
    PPC_INS_FMSUB = 276,
    PPC_INS_FMSUBS = 277,
    PPC_INS_FMUL = 278,
    PPC_INS_FMULS = 279,
    PPC_INS_FNABS = 280,
    PPC_INS_FNEG = 281,
    PPC_INS_FNMADD = 282,
    PPC_INS_FNMADDS = 283,
    PPC_INS_FNMSUB = 284,
    PPC_INS_FNMSUBS = 285,
    PPC_INS_FRE = 286,
    PPC_INS_FRES = 287,
    PPC_INS_FRIM = 288,
    PPC_INS_FRIN = 289,
    PPC_INS_FRIP = 290,
    PPC_INS_FRIZ = 291,
    PPC_INS_FRSP = 292,
    PPC_INS_FRSQRTE = 293,
    PPC_INS_FRSQRTES = 294,
    PPC_INS_FSEL = 295,
    PPC_INS_FSQRT = 296,
    PPC_INS_FSQRTS = 297,
    PPC_INS_FSUB = 298,
    PPC_INS_FSUBS = 299,
    PPC_INS_ICBI = 300,
    PPC_INS_ICBT = 301,
    PPC_INS_ICCCI = 302,
    PPC_INS_ISEL = 303,
    PPC_INS_ISYNC = 304,
    PPC_INS_LA = 305,
    PPC_INS_LBZ = 306,
    PPC_INS_LBZCIX = 307,
    PPC_INS_LBZU = 308,
    PPC_INS_LBZUX = 309,
    PPC_INS_LBZX = 310,
    PPC_INS_LD = 311,
    PPC_INS_LDARX = 312,
    PPC_INS_LDBRX = 313,
    PPC_INS_LDCIX = 314,
    PPC_INS_LDU = 315,
    PPC_INS_LDUX = 316,
    PPC_INS_LDX = 317,
    PPC_INS_LFD = 318,
    PPC_INS_LFDU = 319,
    PPC_INS_LFDUX = 320,
    PPC_INS_LFDX = 321,
    PPC_INS_LFIWAX = 322,
    PPC_INS_LFIWZX = 323,
    PPC_INS_LFS = 324,
    PPC_INS_LFSU = 325,
    PPC_INS_LFSUX = 326,
    PPC_INS_LFSX = 327,
    PPC_INS_LHA = 328,
    PPC_INS_LHAU = 329,
    PPC_INS_LHAUX = 330,
    PPC_INS_LHAX = 331,
    PPC_INS_LHBRX = 332,
    PPC_INS_LHZ = 333,
    PPC_INS_LHZCIX = 334,
    PPC_INS_LHZU = 335,
    PPC_INS_LHZUX = 336,
    PPC_INS_LHZX = 337,
    PPC_INS_LI = 338,
    PPC_INS_LIS = 339,
    PPC_INS_LMW = 340,
    PPC_INS_LSWI = 341,
    PPC_INS_LVEBX = 342,
    PPC_INS_LVEHX = 343,
    PPC_INS_LVEWX = 344,
    PPC_INS_LVSL = 345,
    PPC_INS_LVSR = 346,
    PPC_INS_LVX = 347,
    PPC_INS_LVXL = 348,
    PPC_INS_LWA = 349,
    PPC_INS_LWARX = 350,
    PPC_INS_LWAUX = 351,
    PPC_INS_LWAX = 352,
    PPC_INS_LWBRX = 353,
    PPC_INS_LWZ = 354,
    PPC_INS_LWZCIX = 355,
    PPC_INS_LWZU = 356,
    PPC_INS_LWZUX = 357,
    PPC_INS_LWZX = 358,
    PPC_INS_LXSDX = 359,
    PPC_INS_LXVD2X = 360,
    PPC_INS_LXVDSX = 361,
    PPC_INS_LXVW4X = 362,
    PPC_INS_MBAR = 363,
    PPC_INS_MCRF = 364,
    PPC_INS_MCRFS = 365,
    PPC_INS_MFCR = 366,
    PPC_INS_MFCTR = 367,
    PPC_INS_MFDCR = 368,
    PPC_INS_MFFS = 369,
    PPC_INS_MFLR = 370,
    PPC_INS_MFMSR = 371,
    PPC_INS_MFOCRF = 372,
    PPC_INS_MFSPR = 373,
    PPC_INS_MFSR = 374,
    PPC_INS_MFSRIN = 375,
    PPC_INS_MFTB = 376,
    PPC_INS_MFVSCR = 377,
    PPC_INS_MSYNC = 378,
    PPC_INS_MTCRF = 379,
    PPC_INS_MTCTR = 380,
    PPC_INS_MTDCR = 381,
    PPC_INS_MTFSB0 = 382,
    PPC_INS_MTFSB1 = 383,
    PPC_INS_MTFSF = 384,
    PPC_INS_MTFSFI = 385,
    PPC_INS_MTLR = 386,
    PPC_INS_MTMSR = 387,
    PPC_INS_MTMSRD = 388,
    PPC_INS_MTOCRF = 389,
    PPC_INS_MTSPR = 390,
    PPC_INS_MTSR = 391,
    PPC_INS_MTSRIN = 392,
    PPC_INS_MTVSCR = 393,
    PPC_INS_MULHD = 394,
    PPC_INS_MULHDU = 395,
    PPC_INS_MULHW = 396,
    PPC_INS_MULHWU = 397,
    PPC_INS_MULLD = 398,
    PPC_INS_MULLI = 399,
    PPC_INS_MULLW = 400,
    PPC_INS_NAND = 401,
    PPC_INS_NEG = 402,
    PPC_INS_NOP = 403,
    PPC_INS_ORI = 404,
    PPC_INS_NOR = 405,
    PPC_INS_OR = 406,
    PPC_INS_ORC = 407,
    PPC_INS_ORIS = 408,
    PPC_INS_POPCNTD = 409,
    PPC_INS_POPCNTW = 410,
    PPC_INS_QVALIGNI = 411,
    PPC_INS_QVESPLATI = 412,
    PPC_INS_QVFABS = 413,
    PPC_INS_QVFADD = 414,
    PPC_INS_QVFADDS = 415,
    PPC_INS_QVFCFID = 416,
    PPC_INS_QVFCFIDS = 417,
    PPC_INS_QVFCFIDU = 418,
    PPC_INS_QVFCFIDUS = 419,
    PPC_INS_QVFCMPEQ = 420,
    PPC_INS_QVFCMPGT = 421,
    PPC_INS_QVFCMPLT = 422,
    PPC_INS_QVFCPSGN = 423,
    PPC_INS_QVFCTID = 424,
    PPC_INS_QVFCTIDU = 425,
    PPC_INS_QVFCTIDUZ = 426,
    PPC_INS_QVFCTIDZ = 427,
    PPC_INS_QVFCTIW = 428,
    PPC_INS_QVFCTIWU = 429,
    PPC_INS_QVFCTIWUZ = 430,
    PPC_INS_QVFCTIWZ = 431,
    PPC_INS_QVFLOGICAL = 432,
    PPC_INS_QVFMADD = 433,
    PPC_INS_QVFMADDS = 434,
    PPC_INS_QVFMR = 435,
    PPC_INS_QVFMSUB = 436,
    PPC_INS_QVFMSUBS = 437,
    PPC_INS_QVFMUL = 438,
    PPC_INS_QVFMULS = 439,
    PPC_INS_QVFNABS = 440,
    PPC_INS_QVFNEG = 441,
    PPC_INS_QVFNMADD = 442,
    PPC_INS_QVFNMADDS = 443,
    PPC_INS_QVFNMSUB = 444,
    PPC_INS_QVFNMSUBS = 445,
    PPC_INS_QVFPERM = 446,
    PPC_INS_QVFRE = 447,
    PPC_INS_QVFRES = 448,
    PPC_INS_QVFRIM = 449,
    PPC_INS_QVFRIN = 450,
    PPC_INS_QVFRIP = 451,
    PPC_INS_QVFRIZ = 452,
    PPC_INS_QVFRSP = 453,
    PPC_INS_QVFRSQRTE = 454,
    PPC_INS_QVFRSQRTES = 455,
    PPC_INS_QVFSEL = 456,
    PPC_INS_QVFSUB = 457,
    PPC_INS_QVFSUBS = 458,
    PPC_INS_QVFTSTNAN = 459,
    PPC_INS_QVFXMADD = 460,
    PPC_INS_QVFXMADDS = 461,
    PPC_INS_QVFXMUL = 462,
    PPC_INS_QVFXMULS = 463,
    PPC_INS_QVFXXCPNMADD = 464,
    PPC_INS_QVFXXCPNMADDS = 465,
    PPC_INS_QVFXXMADD = 466,
    PPC_INS_QVFXXMADDS = 467,
    PPC_INS_QVFXXNPMADD = 468,
    PPC_INS_QVFXXNPMADDS = 469,
    PPC_INS_QVGPCI = 470,
    PPC_INS_QVLFCDUX = 471,
    PPC_INS_QVLFCDUXA = 472,
    PPC_INS_QVLFCDX = 473,
    PPC_INS_QVLFCDXA = 474,
    PPC_INS_QVLFCSUX = 475,
    PPC_INS_QVLFCSUXA = 476,
    PPC_INS_QVLFCSX = 477,
    PPC_INS_QVLFCSXA = 478,
    PPC_INS_QVLFDUX = 479,
    PPC_INS_QVLFDUXA = 480,
    PPC_INS_QVLFDX = 481,
    PPC_INS_QVLFDXA = 482,
    PPC_INS_QVLFIWAX = 483,
    PPC_INS_QVLFIWAXA = 484,
    PPC_INS_QVLFIWZX = 485,
    PPC_INS_QVLFIWZXA = 486,
    PPC_INS_QVLFSUX = 487,
    PPC_INS_QVLFSUXA = 488,
    PPC_INS_QVLFSX = 489,
    PPC_INS_QVLFSXA = 490,
    PPC_INS_QVLPCLDX = 491,
    PPC_INS_QVLPCLSX = 492,
    PPC_INS_QVLPCRDX = 493,
    PPC_INS_QVLPCRSX = 494,
    PPC_INS_QVSTFCDUX = 495,
    PPC_INS_QVSTFCDUXA = 496,
    PPC_INS_QVSTFCDUXI = 497,
    PPC_INS_QVSTFCDUXIA = 498,
    PPC_INS_QVSTFCDX = 499,
    PPC_INS_QVSTFCDXA = 500,
    PPC_INS_QVSTFCDXI = 501,
    PPC_INS_QVSTFCDXIA = 502,
    PPC_INS_QVSTFCSUX = 503,
    PPC_INS_QVSTFCSUXA = 504,
    PPC_INS_QVSTFCSUXI = 505,
    PPC_INS_QVSTFCSUXIA = 506,
    PPC_INS_QVSTFCSX = 507,
    PPC_INS_QVSTFCSXA = 508,
    PPC_INS_QVSTFCSXI = 509,
    PPC_INS_QVSTFCSXIA = 510,
    PPC_INS_QVSTFDUX = 511,
    PPC_INS_QVSTFDUXA = 512,
    PPC_INS_QVSTFDUXI = 513,
    PPC_INS_QVSTFDUXIA = 514,
    PPC_INS_QVSTFDX = 515,
    PPC_INS_QVSTFDXA = 516,
    PPC_INS_QVSTFDXI = 517,
    PPC_INS_QVSTFDXIA = 518,
    PPC_INS_QVSTFIWX = 519,
    PPC_INS_QVSTFIWXA = 520,
    PPC_INS_QVSTFSUX = 521,
    PPC_INS_QVSTFSUXA = 522,
    PPC_INS_QVSTFSUXI = 523,
    PPC_INS_QVSTFSUXIA = 524,
    PPC_INS_QVSTFSX = 525,
    PPC_INS_QVSTFSXA = 526,
    PPC_INS_QVSTFSXI = 527,
    PPC_INS_QVSTFSXIA = 528,
    PPC_INS_RFCI = 529,
    PPC_INS_RFDI = 530,
    PPC_INS_RFI = 531,
    PPC_INS_RFID = 532,
    PPC_INS_RFMCI = 533,
    PPC_INS_RLDCL = 534,
    PPC_INS_RLDCR = 535,
    PPC_INS_RLDIC = 536,
    PPC_INS_RLDICL = 537,
    PPC_INS_RLDICR = 538,
    PPC_INS_RLDIMI = 539,
    PPC_INS_RLWIMI = 540,
    PPC_INS_RLWINM = 541,
    PPC_INS_RLWNM = 542,
    PPC_INS_SC = 543,
    PPC_INS_SLBIA = 544,
    PPC_INS_SLBIE = 545,
    PPC_INS_SLBMFEE = 546,
    PPC_INS_SLBMTE = 547,
    PPC_INS_SLD = 548,
    PPC_INS_SLW = 549,
    PPC_INS_SRAD = 550,
    PPC_INS_SRADI = 551,
    PPC_INS_SRAW = 552,
    PPC_INS_SRAWI = 553,
    PPC_INS_SRD = 554,
    PPC_INS_SRW = 555,
    PPC_INS_STB = 556,
    PPC_INS_STBCIX = 557,
    PPC_INS_STBU = 558,
    PPC_INS_STBUX = 559,
    PPC_INS_STBX = 560,
    PPC_INS_STD = 561,
    PPC_INS_STDBRX = 562,
    PPC_INS_STDCIX = 563,
    PPC_INS_STDCX = 564,
    PPC_INS_STDU = 565,
    PPC_INS_STDUX = 566,
    PPC_INS_STDX = 567,
    PPC_INS_STFD = 568,
    PPC_INS_STFDU = 569,
    PPC_INS_STFDUX = 570,
    PPC_INS_STFDX = 571,
    PPC_INS_STFIWX = 572,
    PPC_INS_STFS = 573,
    PPC_INS_STFSU = 574,
    PPC_INS_STFSUX = 575,
    PPC_INS_STFSX = 576,
    PPC_INS_STH = 577,
    PPC_INS_STHBRX = 578,
    PPC_INS_STHCIX = 579,
    PPC_INS_STHU = 580,
    PPC_INS_STHUX = 581,
    PPC_INS_STHX = 582,
    PPC_INS_STMW = 583,
    PPC_INS_STSWI = 584,
    PPC_INS_STVEBX = 585,
    PPC_INS_STVEHX = 586,
    PPC_INS_STVEWX = 587,
    PPC_INS_STVX = 588,
    PPC_INS_STVXL = 589,
    PPC_INS_STW = 590,
    PPC_INS_STWBRX = 591,
    PPC_INS_STWCIX = 592,
    PPC_INS_STWCX = 593,
    PPC_INS_STWU = 594,
    PPC_INS_STWUX = 595,
    PPC_INS_STWX = 596,
    PPC_INS_STXSDX = 597,
    PPC_INS_STXVD2X = 598,
    PPC_INS_STXVW4X = 599,
    PPC_INS_SUBF = 600,
    PPC_INS_SUBFC = 601,
    PPC_INS_SUBFE = 602,
    PPC_INS_SUBFIC = 603,
    PPC_INS_SUBFME = 604,
    PPC_INS_SUBFZE = 605,
    PPC_INS_SYNC = 606,
    PPC_INS_TD = 607,
    PPC_INS_TDI = 608,
    PPC_INS_TLBIA = 609,
    PPC_INS_TLBIE = 610,
    PPC_INS_TLBIEL = 611,
    PPC_INS_TLBIVAX = 612,
    PPC_INS_TLBLD = 613,
    PPC_INS_TLBLI = 614,
    PPC_INS_TLBRE = 615,
    PPC_INS_TLBSX = 616,
    PPC_INS_TLBSYNC = 617,
    PPC_INS_TLBWE = 618,
    PPC_INS_TRAP = 619,
    PPC_INS_TW = 620,
    PPC_INS_TWI = 621,
    PPC_INS_VADDCUW = 622,
    PPC_INS_VADDFP = 623,
    PPC_INS_VADDSBS = 624,
    PPC_INS_VADDSHS = 625,
    PPC_INS_VADDSWS = 626,
    PPC_INS_VADDUBM = 627,
    PPC_INS_VADDUBS = 628,
    PPC_INS_VADDUDM = 629,
    PPC_INS_VADDUHM = 630,
    PPC_INS_VADDUHS = 631,
    PPC_INS_VADDUWM = 632,
    PPC_INS_VADDUWS = 633,
    PPC_INS_VAND = 634,
    PPC_INS_VANDC = 635,
    PPC_INS_VAVGSB = 636,
    PPC_INS_VAVGSH = 637,
    PPC_INS_VAVGSW = 638,
    PPC_INS_VAVGUB = 639,
    PPC_INS_VAVGUH = 640,
    PPC_INS_VAVGUW = 641,
    PPC_INS_VCFSX = 642,
    PPC_INS_VCFUX = 643,
    PPC_INS_VCLZB = 644,
    PPC_INS_VCLZD = 645,
    PPC_INS_VCLZH = 646,
    PPC_INS_VCLZW = 647,
    PPC_INS_VCMPBFP = 648,
    PPC_INS_VCMPEQFP = 649,
    PPC_INS_VCMPEQUB = 650,
    PPC_INS_VCMPEQUD = 651,
    PPC_INS_VCMPEQUH = 652,
    PPC_INS_VCMPEQUW = 653,
    PPC_INS_VCMPGEFP = 654,
    PPC_INS_VCMPGTFP = 655,
    PPC_INS_VCMPGTSB = 656,
    PPC_INS_VCMPGTSD = 657,
    PPC_INS_VCMPGTSH = 658,
    PPC_INS_VCMPGTSW = 659,
    PPC_INS_VCMPGTUB = 660,
    PPC_INS_VCMPGTUD = 661,
    PPC_INS_VCMPGTUH = 662,
    PPC_INS_VCMPGTUW = 663,
    PPC_INS_VCTSXS = 664,
    PPC_INS_VCTUXS = 665,
    PPC_INS_VEQV = 666,
    PPC_INS_VEXPTEFP = 667,
    PPC_INS_VLOGEFP = 668,
    PPC_INS_VMADDFP = 669,
    PPC_INS_VMAXFP = 670,
    PPC_INS_VMAXSB = 671,
    PPC_INS_VMAXSD = 672,
    PPC_INS_VMAXSH = 673,
    PPC_INS_VMAXSW = 674,
    PPC_INS_VMAXUB = 675,
    PPC_INS_VMAXUD = 676,
    PPC_INS_VMAXUH = 677,
    PPC_INS_VMAXUW = 678,
    PPC_INS_VMHADDSHS = 679,
    PPC_INS_VMHRADDSHS = 680,
    PPC_INS_VMINUD = 681,
    PPC_INS_VMINFP = 682,
    PPC_INS_VMINSB = 683,
    PPC_INS_VMINSD = 684,
    PPC_INS_VMINSH = 685,
    PPC_INS_VMINSW = 686,
    PPC_INS_VMINUB = 687,
    PPC_INS_VMINUH = 688,
    PPC_INS_VMINUW = 689,
    PPC_INS_VMLADDUHM = 690,
    PPC_INS_VMRGHB = 691,
    PPC_INS_VMRGHH = 692,
    PPC_INS_VMRGHW = 693,
    PPC_INS_VMRGLB = 694,
    PPC_INS_VMRGLH = 695,
    PPC_INS_VMRGLW = 696,
    PPC_INS_VMSUMMBM = 697,
    PPC_INS_VMSUMSHM = 698,
    PPC_INS_VMSUMSHS = 699,
    PPC_INS_VMSUMUBM = 700,
    PPC_INS_VMSUMUHM = 701,
    PPC_INS_VMSUMUHS = 702,
    PPC_INS_VMULESB = 703,
    PPC_INS_VMULESH = 704,
    PPC_INS_VMULESW = 705,
    PPC_INS_VMULEUB = 706,
    PPC_INS_VMULEUH = 707,
    PPC_INS_VMULEUW = 708,
    PPC_INS_VMULOSB = 709,
    PPC_INS_VMULOSH = 710,
    PPC_INS_VMULOSW = 711,
    PPC_INS_VMULOUB = 712,
    PPC_INS_VMULOUH = 713,
    PPC_INS_VMULOUW = 714,
    PPC_INS_VMULUWM = 715,
    PPC_INS_VNAND = 716,
    PPC_INS_VNMSUBFP = 717,
    PPC_INS_VNOR = 718,
    PPC_INS_VOR = 719,
    PPC_INS_VORC = 720,
    PPC_INS_VPERM = 721,
    PPC_INS_VPKPX = 722,
    PPC_INS_VPKSHSS = 723,
    PPC_INS_VPKSHUS = 724,
    PPC_INS_VPKSWSS = 725,
    PPC_INS_VPKSWUS = 726,
    PPC_INS_VPKUHUM = 727,
    PPC_INS_VPKUHUS = 728,
    PPC_INS_VPKUWUM = 729,
    PPC_INS_VPKUWUS = 730,
    PPC_INS_VPOPCNTB = 731,
    PPC_INS_VPOPCNTD = 732,
    PPC_INS_VPOPCNTH = 733,
    PPC_INS_VPOPCNTW = 734,
    PPC_INS_VREFP = 735,
    PPC_INS_VRFIM = 736,
    PPC_INS_VRFIN = 737,
    PPC_INS_VRFIP = 738,
    PPC_INS_VRFIZ = 739,
    PPC_INS_VRLB = 740,
    PPC_INS_VRLD = 741,
    PPC_INS_VRLH = 742,
    PPC_INS_VRLW = 743,
    PPC_INS_VRSQRTEFP = 744,
    PPC_INS_VSEL = 745,
    PPC_INS_VSL = 746,
    PPC_INS_VSLB = 747,
    PPC_INS_VSLD = 748,
    PPC_INS_VSLDOI = 749,
    PPC_INS_VSLH = 750,
    PPC_INS_VSLO = 751,
    PPC_INS_VSLW = 752,
    PPC_INS_VSPLTB = 753,
    PPC_INS_VSPLTH = 754,
    PPC_INS_VSPLTISB = 755,
    PPC_INS_VSPLTISH = 756,
    PPC_INS_VSPLTISW = 757,
    PPC_INS_VSPLTW = 758,
    PPC_INS_VSR = 759,
    PPC_INS_VSRAB = 760,
    PPC_INS_VSRAD = 761,
    PPC_INS_VSRAH = 762,
    PPC_INS_VSRAW = 763,
    PPC_INS_VSRB = 764,
    PPC_INS_VSRD = 765,
    PPC_INS_VSRH = 766,
    PPC_INS_VSRO = 767,
    PPC_INS_VSRW = 768,
    PPC_INS_VSUBCUW = 769,
    PPC_INS_VSUBFP = 770,
    PPC_INS_VSUBSBS = 771,
    PPC_INS_VSUBSHS = 772,
    PPC_INS_VSUBSWS = 773,
    PPC_INS_VSUBUBM = 774,
    PPC_INS_VSUBUBS = 775,
    PPC_INS_VSUBUDM = 776,
    PPC_INS_VSUBUHM = 777,
    PPC_INS_VSUBUHS = 778,
    PPC_INS_VSUBUWM = 779,
    PPC_INS_VSUBUWS = 780,
    PPC_INS_VSUM2SWS = 781,
    PPC_INS_VSUM4SBS = 782,
    PPC_INS_VSUM4SHS = 783,
    PPC_INS_VSUM4UBS = 784,
    PPC_INS_VSUMSWS = 785,
    PPC_INS_VUPKHPX = 786,
    PPC_INS_VUPKHSB = 787,
    PPC_INS_VUPKHSH = 788,
    PPC_INS_VUPKLPX = 789,
    PPC_INS_VUPKLSB = 790,
    PPC_INS_VUPKLSH = 791,
    PPC_INS_VXOR = 792,
    PPC_INS_WAIT = 793,
    PPC_INS_WRTEE = 794,
    PPC_INS_WRTEEI = 795,
    PPC_INS_XOR = 796,
    PPC_INS_XORI = 797,
    PPC_INS_XORIS = 798,
    PPC_INS_XSABSDP = 799,
    PPC_INS_XSADDDP = 800,
    PPC_INS_XSCMPODP = 801,
    PPC_INS_XSCMPUDP = 802,
    PPC_INS_XSCPSGNDP = 803,
    PPC_INS_XSCVDPSP = 804,
    PPC_INS_XSCVDPSXDS = 805,
    PPC_INS_XSCVDPSXWS = 806,
    PPC_INS_XSCVDPUXDS = 807,
    PPC_INS_XSCVDPUXWS = 808,
    PPC_INS_XSCVSPDP = 809,
    PPC_INS_XSCVSXDDP = 810,
    PPC_INS_XSCVUXDDP = 811,
    PPC_INS_XSDIVDP = 812,
    PPC_INS_XSMADDADP = 813,
    PPC_INS_XSMADDMDP = 814,
    PPC_INS_XSMAXDP = 815,
    PPC_INS_XSMINDP = 816,
    PPC_INS_XSMSUBADP = 817,
    PPC_INS_XSMSUBMDP = 818,
    PPC_INS_XSMULDP = 819,
    PPC_INS_XSNABSDP = 820,
    PPC_INS_XSNEGDP = 821,
    PPC_INS_XSNMADDADP = 822,
    PPC_INS_XSNMADDMDP = 823,
    PPC_INS_XSNMSUBADP = 824,
    PPC_INS_XSNMSUBMDP = 825,
    PPC_INS_XSRDPI = 826,
    PPC_INS_XSRDPIC = 827,
    PPC_INS_XSRDPIM = 828,
    PPC_INS_XSRDPIP = 829,
    PPC_INS_XSRDPIZ = 830,
    PPC_INS_XSREDP = 831,
    PPC_INS_XSRSQRTEDP = 832,
    PPC_INS_XSSQRTDP = 833,
    PPC_INS_XSSUBDP = 834,
    PPC_INS_XSTDIVDP = 835,
    PPC_INS_XSTSQRTDP = 836,
    PPC_INS_XVABSDP = 837,
    PPC_INS_XVABSSP = 838,
    PPC_INS_XVADDDP = 839,
    PPC_INS_XVADDSP = 840,
    PPC_INS_XVCMPEQDP = 841,
    PPC_INS_XVCMPEQSP = 842,
    PPC_INS_XVCMPGEDP = 843,
    PPC_INS_XVCMPGESP = 844,
    PPC_INS_XVCMPGTDP = 845,
    PPC_INS_XVCMPGTSP = 846,
    PPC_INS_XVCPSGNDP = 847,
    PPC_INS_XVCPSGNSP = 848,
    PPC_INS_XVCVDPSP = 849,
    PPC_INS_XVCVDPSXDS = 850,
    PPC_INS_XVCVDPSXWS = 851,
    PPC_INS_XVCVDPUXDS = 852,
    PPC_INS_XVCVDPUXWS = 853,
    PPC_INS_XVCVSPDP = 854,
    PPC_INS_XVCVSPSXDS = 855,
    PPC_INS_XVCVSPSXWS = 856,
    PPC_INS_XVCVSPUXDS = 857,
    PPC_INS_XVCVSPUXWS = 858,
    PPC_INS_XVCVSXDDP = 859,
    PPC_INS_XVCVSXDSP = 860,
    PPC_INS_XVCVSXWDP = 861,
    PPC_INS_XVCVSXWSP = 862,
    PPC_INS_XVCVUXDDP = 863,
    PPC_INS_XVCVUXDSP = 864,
    PPC_INS_XVCVUXWDP = 865,
    PPC_INS_XVCVUXWSP = 866,
    PPC_INS_XVDIVDP = 867,
    PPC_INS_XVDIVSP = 868,
    PPC_INS_XVMADDADP = 869,
    PPC_INS_XVMADDASP = 870,
    PPC_INS_XVMADDMDP = 871,
    PPC_INS_XVMADDMSP = 872,
    PPC_INS_XVMAXDP = 873,
    PPC_INS_XVMAXSP = 874,
    PPC_INS_XVMINDP = 875,
    PPC_INS_XVMINSP = 876,
    PPC_INS_XVMSUBADP = 877,
    PPC_INS_XVMSUBASP = 878,
    PPC_INS_XVMSUBMDP = 879,
    PPC_INS_XVMSUBMSP = 880,
    PPC_INS_XVMULDP = 881,
    PPC_INS_XVMULSP = 882,
    PPC_INS_XVNABSDP = 883,
    PPC_INS_XVNABSSP = 884,
    PPC_INS_XVNEGDP = 885,
    PPC_INS_XVNEGSP = 886,
    PPC_INS_XVNMADDADP = 887,
    PPC_INS_XVNMADDASP = 888,
    PPC_INS_XVNMADDMDP = 889,
    PPC_INS_XVNMADDMSP = 890,
    PPC_INS_XVNMSUBADP = 891,
    PPC_INS_XVNMSUBASP = 892,
    PPC_INS_XVNMSUBMDP = 893,
    PPC_INS_XVNMSUBMSP = 894,
    PPC_INS_XVRDPI = 895,
    PPC_INS_XVRDPIC = 896,
    PPC_INS_XVRDPIM = 897,
    PPC_INS_XVRDPIP = 898,
    PPC_INS_XVRDPIZ = 899,
    PPC_INS_XVREDP = 900,
    PPC_INS_XVRESP = 901,
    PPC_INS_XVRSPI = 902,
    PPC_INS_XVRSPIC = 903,
    PPC_INS_XVRSPIM = 904,
    PPC_INS_XVRSPIP = 905,
    PPC_INS_XVRSPIZ = 906,
    PPC_INS_XVRSQRTEDP = 907,
    PPC_INS_XVRSQRTESP = 908,
    PPC_INS_XVSQRTDP = 909,
    PPC_INS_XVSQRTSP = 910,
    PPC_INS_XVSUBDP = 911,
    PPC_INS_XVSUBSP = 912,
    PPC_INS_XVTDIVDP = 913,
    PPC_INS_XVTDIVSP = 914,
    PPC_INS_XVTSQRTDP = 915,
    PPC_INS_XVTSQRTSP = 916,
    PPC_INS_XXLAND = 917,
    PPC_INS_XXLANDC = 918,
    PPC_INS_XXLEQV = 919,
    PPC_INS_XXLNAND = 920,
    PPC_INS_XXLNOR = 921,
    PPC_INS_XXLOR = 922,
    PPC_INS_XXLORC = 923,
    PPC_INS_XXLXOR = 924,
    PPC_INS_XXMRGHW = 925,
    PPC_INS_XXMRGLW = 926,
    PPC_INS_XXPERMDI = 927,
    PPC_INS_XXSEL = 928,
    PPC_INS_XXSLDWI = 929,
    PPC_INS_XXSPLTW = 930,
    PPC_INS_BCA = 931,
    PPC_INS_BCLA = 932,

    // extra & alias instructions
    PPC_INS_SLWI = 933,
    PPC_INS_SRWI = 934,
    PPC_INS_SLDI = 935,

    PPC_INS_BTA = 936,
    PPC_INS_CRSET = 937,
    PPC_INS_CRNOT = 938,
    PPC_INS_CRMOVE = 939,
    PPC_INS_CRCLR = 940,
    PPC_INS_MFBR0 = 941,
    PPC_INS_MFBR1 = 942,
    PPC_INS_MFBR2 = 943,
    PPC_INS_MFBR3 = 944,
    PPC_INS_MFBR4 = 945,
    PPC_INS_MFBR5 = 946,
    PPC_INS_MFBR6 = 947,
    PPC_INS_MFBR7 = 948,
    PPC_INS_MFXER = 949,
    PPC_INS_MFRTCU = 950,
    PPC_INS_MFRTCL = 951,
    PPC_INS_MFDSCR = 952,
    PPC_INS_MFDSISR = 953,
    PPC_INS_MFDAR = 954,
    PPC_INS_MFSRR2 = 955,
    PPC_INS_MFSRR3 = 956,
    PPC_INS_MFCFAR = 957,
    PPC_INS_MFAMR = 958,
    PPC_INS_MFPID = 959,
    PPC_INS_MFTBLO = 960,
    PPC_INS_MFTBHI = 961,
    PPC_INS_MFDBATU = 962,
    PPC_INS_MFDBATL = 963,
    PPC_INS_MFIBATU = 964,
    PPC_INS_MFIBATL = 965,
    PPC_INS_MFDCCR = 966,
    PPC_INS_MFICCR = 967,
    PPC_INS_MFDEAR = 968,
    PPC_INS_MFESR = 969,
    PPC_INS_MFSPEFSCR = 970,
    PPC_INS_MFTCR = 971,
    PPC_INS_MFASR = 972,
    PPC_INS_MFPVR = 973,
    PPC_INS_MFTBU = 974,
    PPC_INS_MTCR = 975,
    PPC_INS_MTBR0 = 976,
    PPC_INS_MTBR1 = 977,
    PPC_INS_MTBR2 = 978,
    PPC_INS_MTBR3 = 979,
    PPC_INS_MTBR4 = 980,
    PPC_INS_MTBR5 = 981,
    PPC_INS_MTBR6 = 982,
    PPC_INS_MTBR7 = 983,
    PPC_INS_MTXER = 984,
    PPC_INS_MTDSCR = 985,
    PPC_INS_MTDSISR = 986,
    PPC_INS_MTDAR = 987,
    PPC_INS_MTSRR2 = 988,
    PPC_INS_MTSRR3 = 989,
    PPC_INS_MTCFAR = 990,
    PPC_INS_MTAMR = 991,
    PPC_INS_MTPID = 992,
    PPC_INS_MTTBL = 993,
    PPC_INS_MTTBU = 994,
    PPC_INS_MTTBLO = 995,
    PPC_INS_MTTBHI = 996,
    PPC_INS_MTDBATU = 997,
    PPC_INS_MTDBATL = 998,
    PPC_INS_MTIBATU = 999,
    PPC_INS_MTIBATL = 1000,
    PPC_INS_MTDCCR = 1001,
    PPC_INS_MTICCR = 1002,
    PPC_INS_MTDEAR = 1003,
    PPC_INS_MTESR = 1004,
    PPC_INS_MTSPEFSCR = 1005,
    PPC_INS_MTTCR = 1006,
    PPC_INS_NOT = 1007,
    PPC_INS_MR = 1008,
    PPC_INS_ROTLD = 1009,
    PPC_INS_ROTLDI = 1010,
    PPC_INS_CLRLDI = 1011,
    PPC_INS_ROTLWI = 1012,
    PPC_INS_CLRLWI = 1013,
    PPC_INS_ROTLW = 1014,
    PPC_INS_SUB = 1015,
    PPC_INS_SUBC = 1016,
    PPC_INS_LWSYNC = 1017,
    PPC_INS_PTESYNC = 1018,
    PPC_INS_TDLT = 1019,
    PPC_INS_TDEQ = 1020,
    PPC_INS_TDGT = 1021,
    PPC_INS_TDNE = 1022,
    PPC_INS_TDLLT = 1023,
    PPC_INS_TDLGT = 1024,
    PPC_INS_TDU = 1025,
    PPC_INS_TDLTI = 1026,
    PPC_INS_TDEQI = 1027,
    PPC_INS_TDGTI = 1028,
    PPC_INS_TDNEI = 1029,
    PPC_INS_TDLLTI = 1030,
    PPC_INS_TDLGTI = 1031,
    PPC_INS_TDUI = 1032,
    PPC_INS_TLBREHI = 1033,
    PPC_INS_TLBRELO = 1034,
    PPC_INS_TLBWEHI = 1035,
    PPC_INS_TLBWELO = 1036,
    PPC_INS_TWLT = 1037,
    PPC_INS_TWEQ = 1038,
    PPC_INS_TWGT = 1039,
    PPC_INS_TWNE = 1040,
    PPC_INS_TWLLT = 1041,
    PPC_INS_TWLGT = 1042,
    PPC_INS_TWU = 1043,
    PPC_INS_TWLTI = 1044,
    PPC_INS_TWEQI = 1045,
    PPC_INS_TWGTI = 1046,
    PPC_INS_TWNEI = 1047,
    PPC_INS_TWLLTI = 1048,
    PPC_INS_TWLGTI = 1049,
    PPC_INS_TWUI = 1050,
    PPC_INS_WAITRSV = 1051,
    PPC_INS_WAITIMPL = 1052,
    PPC_INS_XNOP = 1053,
    PPC_INS_XVMOVDP = 1054,
    PPC_INS_XVMOVSP = 1055,
    PPC_INS_XXSPLTD = 1056,
    PPC_INS_XXMRGHD = 1057,
    PPC_INS_XXMRGLD = 1058,
    PPC_INS_XXSWAPD = 1059,
    PPC_INS_BT = 1060,
    PPC_INS_BF = 1061,
    PPC_INS_BDNZT = 1062,
    PPC_INS_BDNZF = 1063,
    PPC_INS_BDZF = 1064,
    PPC_INS_BDZT = 1065,
    PPC_INS_BFA = 1066,
    PPC_INS_BDNZTA = 1067,
    PPC_INS_BDNZFA = 1068,
    PPC_INS_BDZTA = 1069,
    PPC_INS_BDZFA = 1070,
    PPC_INS_BTCTR = 1071,
    PPC_INS_BFCTR = 1072,
    PPC_INS_BTCTRL = 1073,
    PPC_INS_BFCTRL = 1074,
    PPC_INS_BTL = 1075,
    PPC_INS_BFL = 1076,
    PPC_INS_BDNZTL = 1077,
    PPC_INS_BDNZFL = 1078,
    PPC_INS_BDZTL = 1079,
    PPC_INS_BDZFL = 1080,
    PPC_INS_BTLA = 1081,
    PPC_INS_BFLA = 1082,
    PPC_INS_BDNZTLA = 1083,
    PPC_INS_BDNZFLA = 1084,
    PPC_INS_BDZTLA = 1085,
    PPC_INS_BDZFLA = 1086,
    PPC_INS_BTLR = 1087,
    PPC_INS_BFLR = 1088,
    PPC_INS_BDNZTLR = 1089,
    PPC_INS_BDZTLR = 1090,
    PPC_INS_BDZFLR = 1091,
    PPC_INS_BTLRL = 1092,
    PPC_INS_BFLRL = 1093,
    PPC_INS_BDNZTLRL = 1094,
    PPC_INS_BDNZFLRL = 1095,
    PPC_INS_BDZTLRL = 1096,
    PPC_INS_BDZFLRL = 1097,

    // QPX
    PPC_INS_QVFAND = 1098,
    PPC_INS_QVFCLR = 1099,
    PPC_INS_QVFANDC = 1100,
    PPC_INS_QVFCTFB = 1101,
    PPC_INS_QVFXOR = 1102,
    PPC_INS_QVFOR = 1103,
    PPC_INS_QVFNOR = 1104,
    PPC_INS_QVFEQU = 1105,
    PPC_INS_QVFNOT = 1106,
    PPC_INS_QVFORC = 1107,
    PPC_INS_QVFNAND = 1108,
    PPC_INS_QVFSET = 1109,

    PPC_INS_ENDING = 1110 // <-- mark the end of the list of instructions
}

/// Group of PPC instructions
enum ppc_insn_group
{
    PPC_GRP_INVALID = 0, ///< = CS_GRP_INVALID

    // Generic groups
    // all jump instructions (conditional+direct+indirect jumps)
    PPC_GRP_JUMP = 1, ///< = CS_GRP_JUMP

    // Architecture-specific groups
    PPC_GRP_ALTIVEC = 128,
    PPC_GRP_MODE32 = 129,
    PPC_GRP_MODE64 = 130,
    PPC_GRP_BOOKE = 131,
    PPC_GRP_NOTBOOKE = 132,
    PPC_GRP_SPE = 133,
    PPC_GRP_VSX = 134,
    PPC_GRP_E500 = 135,
    PPC_GRP_PPC4XX = 136,
    PPC_GRP_PPC6XX = 137,
    PPC_GRP_ICBT = 138,
    PPC_GRP_P8ALTIVEC = 139,
    PPC_GRP_P8VECTOR = 140,
    PPC_GRP_QPX = 141,

    PPC_GRP_ENDING = 142 // <-- mark the end of the list of groups
}
