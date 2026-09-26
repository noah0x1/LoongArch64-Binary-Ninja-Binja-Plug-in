#ifndef LA64_H
#define LA64_H

#define LA_MAX_OPS    4
#define LA_MAX_SPECS  128
#define LA_NBUCKETS   4096

#define LA_T_GPR   0
#define LA_T_FPR   1
#define LA_T_VR    2
#define LA_T_XR    3
#define LA_T_FCC   4
#define LA_T_FCSR  5
#define LA_T_SCR   6
#define LA_T_IMM   7
#define LA_T_UIMM  8
#define LA_T_ADDR  9

#define LA_K_UFIELD   0
#define LA_K_SFIELD   1
#define LA_K_SPLIT21  2
#define LA_K_SPLIT26  3

#define LA_S_NONE   0
#define LA_S_RD     1
#define LA_S_RJ     2
#define LA_S_RK     3
#define LA_S_RA     4
#define LA_S_FD     5
#define LA_S_FJ     6
#define LA_S_FK     7
#define LA_S_FA     8
#define LA_S_VD     9
#define LA_S_VJ    10
#define LA_S_VK    11
#define LA_S_VA    12
#define LA_S_XD    13
#define LA_S_XJ    14
#define LA_S_XK    15
#define LA_S_XA    16
#define LA_S_CD    17
#define LA_S_CJ    18
#define LA_S_CA    19
#define LA_S_FCSRD 20
#define LA_S_FCSRJ 21
#define LA_S_SCRD  22
#define LA_S_SCRJ  23

#define LA_SPEC_KIND    0
#define LA_SPEC_TYPE    1
#define LA_SPEC_POS     2
#define LA_SPEC_WIDTH   3
#define LA_SPEC_SHIFT   4
#define LA_SPEC_ADD     5
#define LA_SPEC_PCREL   6
#define LA_SPEC_SLOT    7
#define LA_SPEC_SIZE    8

#define LA_OPC_MATCH    0
#define LA_OPC_MASK     4
#define LA_OPC_NAME     8
#define LA_OPC_SPECS   16
#define LA_OPC_SIZE    24

#define LA_INFO_NOPS    0
#define LA_INFO_SPEC    1
#define LA_INFO_SIZE    8

#define LA_OPND_VALUE   0
#define LA_OPND_TYPE    8
#define LA_OPND_SLOT    9
#define LA_OPND_SIZE   16

#define LA_INSN_ADDR    0
#define LA_INSN_WORD    8
#define LA_INSN_INDEX  12
#define LA_INSN_NOPS   14
#define LA_INSN_OPS    16
#define LA_INSN_SIZE   (LA_INSN_OPS + LA_MAX_OPS * LA_OPND_SIZE)

#define LA_REG_GPR(n)    (n)
#define LA_REG_XR(n)     (32 + 4 * (n))
#define LA_REG_VR(n)     (33 + 4 * (n))
#define LA_REG_FPR(n)    (34 + 4 * (n))
#define LA_REG_FPRS(n)   (35 + 4 * (n))
#define LA_REG_FCC(n)    (160 + (n))
#define LA_REG_FCSR(n)   (168 + 2 * (n))
#define LA_REG_SCR(n)    (169 + 2 * (n))
#define LA_REG_EFLAGS    176
#define LA_REG_FTOP      177
#define LA_REG_PC        178
#define LA_REG_COUNT     179

#define LA_REG_ZERO 0
#define LA_REG_RA   1
#define LA_REG_TP   2
#define LA_REG_SP   3
#define LA_REG_A(n) (4 + (n))
#define LA_REG_T(n) (12 + (n))
#define LA_REG_FP   22
#define LA_REG_S(n) (23 + (n))

#ifndef __ASSEMBLER__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct la_spec {
	uint8_t kind, type, pos, width, shift, add, pcrel, slot;
} la_spec;

typedef struct la_opcode {
	uint32_t match;
	uint32_t mask;
	const char *name;
	const char *specs;
} la_opcode;

typedef struct la_opinfo {
	uint8_t nops;
	uint8_t spec[LA_MAX_OPS];
	uint8_t pad[3];
} la_opinfo;

typedef struct la_operand {
	int64_t value;
	uint8_t type;
	uint8_t slot;
	uint8_t pad[6];
} la_operand;

typedef struct la_insn {
	uint64_t addr;
	uint32_t word;
	uint16_t index;
	uint8_t nops;
	uint8_t pad;
	la_operand ops[LA_MAX_OPS];
} la_insn;

#include <assert.h>
static_assert(sizeof(la_spec) == LA_SPEC_SIZE, "la_spec");
static_assert(sizeof(la_opcode) == LA_OPC_SIZE, "la_opcode");
static_assert(__builtin_offsetof(la_opcode, mask) == LA_OPC_MASK, "la_opcode.mask");
static_assert(sizeof(la_opinfo) == LA_INFO_SIZE, "la_opinfo");
static_assert(__builtin_offsetof(la_opinfo, spec) == LA_INFO_SPEC, "la_opinfo.spec");
static_assert(sizeof(la_operand) == LA_OPND_SIZE, "la_operand");
static_assert(__builtin_offsetof(la_operand, type) == LA_OPND_TYPE, "la_operand.type");
static_assert(__builtin_offsetof(la_operand, slot) == LA_OPND_SLOT, "la_operand.slot");
static_assert(__builtin_offsetof(la_insn, word) == LA_INSN_WORD, "la_insn.word");
static_assert(__builtin_offsetof(la_insn, index) == LA_INSN_INDEX, "la_insn.index");
static_assert(__builtin_offsetof(la_insn, nops) == LA_INSN_NOPS, "la_insn.nops");
static_assert(__builtin_offsetof(la_insn, ops) == LA_INSN_OPS, "la_insn.ops");
static_assert(sizeof(la_insn) == LA_INSN_SIZE, "la_insn");

#if defined(__GNUC__)
#define LA_HIDDEN __attribute__((visibility("hidden")))
#else
#define LA_HIDDEN
#endif

extern const la_opcode la_opcodes[] LA_HIDDEN;
extern const unsigned la_opcode_count LA_HIDDEN;

extern la_spec la_specs[LA_MAX_SPECS] LA_HIDDEN;
extern la_opinfo *la_info LA_HIDDEN;
extern uint32_t la_bucket_start[LA_NBUCKETS + 1] LA_HIDDEN;
extern uint16_t *la_bucket_list LA_HIDDEN;

LA_HIDDEN bool la_init(void);
LA_HIDDEN const char *la_name(const la_insn *insn);
LA_HIDDEN const char *la_reg_name(unsigned type, uint64_t value);
LA_HIDDEN const char *la_alias(const la_insn *insn, la_operand *ops, unsigned *nops);
LA_HIDDEN uint64_t la_pcrel_value(const la_insn *insn);

LA_HIDDEN int64_t la_sext(uint64_t value, unsigned bits);
LA_HIDDEN int64_t la_split21(uint32_t w);
LA_HIDDEN int64_t la_split26(uint32_t w);
LA_HIDDEN int la_lookup(uint32_t word);
LA_HIDDEN int64_t la_extract(uint32_t word, uint64_t addr, const la_spec *spec);
LA_HIDDEN bool la_decode(const uint8_t *data, size_t len, uint64_t addr, la_insn *out);
LA_HIDDEN uint64_t la_pcrel(uint64_t pc, int64_t imm, unsigned kind);

#endif
#endif
