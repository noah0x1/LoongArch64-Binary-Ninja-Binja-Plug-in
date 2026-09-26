#include <stdlib.h>
#include <string.h>

#include "la64_bn.h"

typedef size_t E;
typedef void (*lift_fn)(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il);

#define M64 0xffffffffffffffffULL

static inline E ex(BNLowLevelILFunction *il, BNLowLevelILOperation op, size_t size,
                   uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
	return BNLowLevelILAddExpr(il, op, size, 0, a, b, c, d);
}

static inline void il_append(BNLowLevelILFunction *il, E e) { BNLowLevelILAddInstruction(il, e); }
static inline E il_const(BNLowLevelILFunction *il, size_t sz, uint64_t v) { return ex(il, LLIL_CONST, sz, v, 0, 0, 0); }
static inline E il_const_ptr(BNLowLevelILFunction *il, size_t sz, uint64_t v) { return ex(il, LLIL_CONST_PTR, sz, v, 0, 0, 0); }
static inline E il_reg(BNLowLevelILFunction *il, size_t sz, uint32_t r) { return ex(il, LLIL_REG, sz, r, 0, 0, 0); }
static inline E il_set_reg(BNLowLevelILFunction *il, size_t sz, uint32_t r, E v) { return ex(il, LLIL_SET_REG, sz, r, v, 0, 0); }
static inline E il_load(BNLowLevelILFunction *il, size_t sz, E a) { return ex(il, LLIL_LOAD, sz, a, 0, 0, 0); }
static inline E il_store(BNLowLevelILFunction *il, size_t sz, E a, E v) { return ex(il, LLIL_STORE, sz, a, v, 0, 0); }
static inline E il_nop(BNLowLevelILFunction *il) { return ex(il, LLIL_NOP, 0, 0, 0, 0, 0); }
static inline E il_undefined(BNLowLevelILFunction *il) { return ex(il, LLIL_UNDEF, 0, 0, 0, 0, 0); }
static inline E il_jump(BNLowLevelILFunction *il, E d) { return ex(il, LLIL_JUMP, 0, d, 0, 0, 0); }
static inline E il_call(BNLowLevelILFunction *il, E d) { return ex(il, LLIL_CALL, 0, d, 0, 0, 0); }
static inline E il_ret(BNLowLevelILFunction *il, E d) { return ex(il, LLIL_RET, 0, d, 0, 0, 0); }
static inline E il_system_call(BNLowLevelILFunction *il) { return ex(il, LLIL_SYSCALL, 0, 0, 0, 0, 0); }
static inline E il_no_ret(BNLowLevelILFunction *il) { return ex(il, LLIL_NORET, 0, 0, 0, 0, 0); }
static inline E il_trap(BNLowLevelILFunction *il, uint64_t code) { return ex(il, LLIL_TRAP, 0, code, 0, 0, 0); }
static inline E il_un(BNLowLevelILFunction *il, BNLowLevelILOperation op, size_t sz, E a) { return ex(il, op, sz, a, 0, 0, 0); }
static inline E il_bin(BNLowLevelILFunction *il, BNLowLevelILOperation op, size_t sz, E a, E b) { return ex(il, op, sz, a, b, 0, 0); }

static inline E il_float_one(BNLowLevelILFunction *il, size_t sz)
{
	return ex(il, LLIL_FLOAT_CONST, sz, sz == 4 ? 0x3f800000ULL : 0x3ff0000000000000ULL, 0, 0, 0);
}

#define il_add(il, s, a, b)  il_bin(il, LLIL_ADD, s, a, b)
#define il_sub(il, s, a, b)  il_bin(il, LLIL_SUB, s, a, b)
#define il_and(il, s, a, b)  il_bin(il, LLIL_AND, s, a, b)
#define il_or(il, s, a, b)   il_bin(il, LLIL_OR, s, a, b)
#define il_xor(il, s, a, b)  il_bin(il, LLIL_XOR, s, a, b)
#define il_lsl(il, s, a, b)  il_bin(il, LLIL_LSL, s, a, b)
#define il_lsr(il, s, a, b)  il_bin(il, LLIL_LSR, s, a, b)
#define il_asr(il, s, a, b)  il_bin(il, LLIL_ASR, s, a, b)
#define il_mul(il, s, a, b)  il_bin(il, LLIL_MUL, s, a, b)
#define il_not(il, s, a)     il_un(il, LLIL_NOT, s, a)
#define il_neg(il, s, a)     il_un(il, LLIL_NEG, s, a)
#define il_sx(il, s, a)      il_un(il, LLIL_SX, s, a)
#define il_zx(il, s, a)      il_un(il, LLIL_ZX, s, a)
#define il_low(il, s, a)     il_un(il, LLIL_LOW_PART, s, a)
#define il_b2i(il, s, a)     il_un(il, LLIL_BOOL_TO_INT, s, a)

#define NAME       (la_name(insn))
#define V(k)       (insn->ops[k].value)
#define R(k)       ((unsigned)insn->ops[k].value)

static bool starts(const char *s, const char *prefix) { return !strncmp(s, prefix, strlen(prefix)); }
static bool ends(const char *s, const char *suffix)
{
	size_t a = strlen(s), b = strlen(suffix);
	return a >= b && !strcmp(s + a - b, suffix);
}

static uint32_t fpr_name(unsigned n, size_t size) { return size == 4 ? LA_REG_FPRS(n) : LA_REG_FPR(n); }

static E r(BNLowLevelILFunction *il, unsigned n)
{
	return n == 0 ? il_const(il, 8, 0) : il_reg(il, 8, LA_REG_GPR(n));
}

static E r32(BNLowLevelILFunction *il, unsigned n)
{
	return n == 0 ? il_const(il, 4, 0) : il_low(il, 4, il_reg(il, 8, LA_REG_GPR(n)));
}

static E rn(BNLowLevelILFunction *il, unsigned n, size_t size)
{
	if (size == 8)
		return r(il, n);
	return n == 0 ? il_const(il, size, 0) : il_low(il, size, il_reg(il, 8, LA_REG_GPR(n)));
}

static void set(BNLowLevelILFunction *il, unsigned n, E expr)
{
	if (n == 0)
		il_append(il, il_nop(il));
	else
		il_append(il, il_set_reg(il, 8, LA_REG_GPR(n), expr));
}

static void setw(BNLowLevelILFunction *il, unsigned n, E expr32) { set(il, n, il_sx(il, 8, expr32)); }
static E f(BNLowLevelILFunction *il, unsigned n, size_t size) { return il_reg(il, size, fpr_name(n, size)); }
static void fset(BNLowLevelILFunction *il, unsigned n, size_t size, E expr)
{
	il_append(il, il_set_reg(il, size, fpr_name(n, size), expr));
}
static size_t fsize(const char *name) { return ends(name, ".s") ? 4 : 8; }

static void lift_intrinsic(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il);

static const struct { const char *name; BNLowLevelILOperation op; bool is32; } OP3[] = {
	{ "add.w", LLIL_ADD, true },   { "add.d", LLIL_ADD, false },
	{ "sub.w", LLIL_SUB, true },   { "sub.d", LLIL_SUB, false },
	{ "and", LLIL_AND, false },    { "or", LLIL_OR, false },     { "xor", LLIL_XOR, false },
	{ "mul.w", LLIL_MUL, true },   { "mul.d", LLIL_MUL, false },
	{ "div.w", LLIL_DIVS, true },  { "div.d", LLIL_DIVS, false },
	{ "div.wu", LLIL_DIVU, true }, { "div.du", LLIL_DIVU, false },
	{ "mod.w", LLIL_MODS, true },  { "mod.d", LLIL_MODS, false },
	{ "mod.wu", LLIL_MODU, true }, { "mod.du", LLIL_MODU, false },
};

static void lift_op3(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1), rk = R(2);
	size_t i = 0;
	while (strcmp(OP3[i].name, NAME))
		i++;
	if (!strcmp(NAME, "or") && rk == 0)
		set(il, rd, r(il, rj));
	else if (OP3[i].is32)
		setw(il, rd, il_bin(il, OP3[i].op, 4, r32(il, rj), r32(il, rk)));
	else
		set(il, rd, il_bin(il, OP3[i].op, 8, r(il, rj), r(il, rk)));
}

static void lift_op3_not(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1), rk = R(2);
	E v;
	if (!strcmp(NAME, "nor"))
		v = il_not(il, 8, il_or(il, 8, r(il, rj), r(il, rk)));
	else if (!strcmp(NAME, "andn"))
		v = il_and(il, 8, r(il, rj), il_not(il, 8, r(il, rk)));
	else
		v = il_or(il, 8, r(il, rj), il_not(il, 8, r(il, rk)));
	set(il, rd, v);
}

static void lift_slt(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1);
	E b = insn->ops[2].slot == LA_S_RK ? r(il, R(2)) : il_const(il, 8, (uint64_t)V(2));
	E cmp;
	if (!strcmp(NAME, "slt") || !strcmp(NAME, "slti"))
		cmp = il_bin(il, LLIL_CMP_SLT, 8, r(il, rj), b);
	else
		cmp = il_bin(il, LLIL_CMP_ULT, 8, r(il, rj), b);
	set(il, rd, il_b2i(il, 8, cmp));
}

static void lift_mask(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1), rk = R(2);
	E cond;
	if (!strcmp(NAME, "maskeqz"))
		cond = il_bin(il, LLIL_CMP_NE, 8, r(il, rk), il_const(il, 8, 0));
	else
		cond = il_bin(il, LLIL_CMP_E, 8, r(il, rk), il_const(il, 8, 0));
	set(il, rd, il_and(il, 8, r(il, rj), il_neg(il, 8, il_b2i(il, 8, cond))));
}

static void lift_addi_w(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1);
	uint64_t imm = (uint64_t)V(2);
	if (rj == 0)
		set(il, rd, il_const(il, 8, imm));
	else
		setw(il, rd, il_add(il, 4, r32(il, rj), il_const(il, 4, imm)));
}

static void lift_addi_d(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1);
	uint64_t imm = (uint64_t)V(2);
	if (!strcmp(NAME, "addu16i.d"))
		imm <<= 16;
	if (rj == 0)
		set(il, rd, il_const(il, 8, imm));
	else if (imm == 0)
		set(il, rd, r(il, rj));
	else
		set(il, rd, il_add(il, 8, r(il, rj), il_const(il, 8, imm)));
}

static void lift_logic_imm(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1);
	uint64_t imm = (uint64_t)V(2);
	if (rj == 0 && strcmp(NAME, "andi")) {
		set(il, rd, il_const(il, 8, imm));
		return;
	}
	BNLowLevelILOperation op = !strcmp(NAME, "andi") ? LLIL_AND : !strcmp(NAME, "ori") ? LLIL_OR : LLIL_XOR;
	set(il, rd, il_bin(il, op, 8, r(il, rj), il_const(il, 8, imm)));
}

static void lift_lu12i(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	set(il, R(0), il_const(il, 8, (uint64_t)V(1) << 12));
}

static void lift_lu32i(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0);
	E low = il_and(il, 8, r(il, rd), il_const(il, 8, 0xffffffffULL));
	set(il, rd, il_or(il, 8, low, il_const(il, 8, (uint64_t)V(1) << 32)));
}

static void lift_lu52i(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1);
	uint64_t hi = (uint64_t)V(2) << 52;
	if (rj == 0) {
		set(il, rd, il_const(il, 8, hi));
	} else {
		E low = il_and(il, 8, r(il, rj), il_const(il, 8, 0x000fffffffffffffULL));
		set(il, rd, il_or(il, 8, low, il_const(il, 8, hi)));
	}
}

static void lift_pcrel(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	set(il, R(0), il_const_ptr(il, 8, la_pcrel_value(insn)));
}

static BNLowLevelILOperation shift_op(const char *name)
{
	if (starts(name, "sll"))
		return LLIL_LSL;
	if (starts(name, "srl"))
		return LLIL_LSR;
	if (starts(name, "sra"))
		return LLIL_ASR;
	return LLIL_ROR;
}

static void lift_shift_reg(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1), rk = R(2);
	BNLowLevelILOperation op = shift_op(NAME);
	if (ends(NAME, ".w")) {
		E amount = il_and(il, 8, r(il, rk), il_const(il, 8, 31));
		setw(il, rd, il_bin(il, op, 4, r32(il, rj), amount));
	} else {
		E amount = il_and(il, 8, r(il, rk), il_const(il, 8, 63));
		set(il, rd, il_bin(il, op, 8, r(il, rj), amount));
	}
}

static void lift_shift_imm(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1);
	uint64_t sa = (uint64_t)V(2);
	BNLowLevelILOperation op = shift_op(NAME);
	if (ends(NAME, ".w"))
		setw(il, rd, sa == 0 ? r32(il, rj) : il_bin(il, op, 4, r32(il, rj), il_const(il, 1, sa)));
	else
		set(il, rd, sa == 0 ? r(il, rj) : il_bin(il, op, 8, r(il, rj), il_const(il, 1, sa)));
}

static void lift_alsl(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1), rk = R(2);
	uint64_t sa = (uint64_t)V(3);
	if (!strcmp(NAME, "alsl.d")) {
		E v = il_lsl(il, 8, r(il, rj), il_const(il, 1, sa));
		set(il, rd, rk == 0 ? v : il_add(il, 8, v, r(il, rk)));
		return;
	}
	E v = il_lsl(il, 4, r32(il, rj), il_const(il, 1, sa));
	if (rk != 0)
		v = il_add(il, 4, v, r32(il, rk));
	if (!strcmp(NAME, "alsl.w"))
		setw(il, rd, v);
	else
		set(il, rd, il_zx(il, 8, v));
}

static void lift_bytepick(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1), rk = R(2);
	uint64_t sa = (uint64_t)V(3);
	unsigned bits = !strcmp(NAME, "bytepick.w") ? 32 : 64;
	size_t size = bits / 8;
	E v;
	if (sa == 0)
		v = rn(il, rk, size);
	else
		v = il_or(il, size,
		          il_lsl(il, size, rn(il, rk, size), il_const(il, 1, 8 * sa)),
		          il_lsr(il, size, rn(il, rj, size), il_const(il, 1, bits - 8 * sa)));
	if (size == 4)
		setw(il, rd, v);
	else
		set(il, rd, v);
}

static void lift_ext(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	size_t size = !strcmp(NAME, "ext.w.b") ? 1 : 2;
	set(il, R(0), il_sx(il, 8, rn(il, R(1), size)));
}

static void lift_bstr(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1);
	int64_t msb = V(2), lsb = V(3);
	if (msb < lsb) {
		il_append(il, il_undefined(il));
		return;
	}
	size_t size = ends(NAME, ".w") ? 4 : 8;
	uint64_t full = size == 8 ? M64 : (1ULL << (size * 8)) - 1;
	unsigned width = (unsigned)(msb - lsb + 1);
	uint64_t field = width >= 64 ? M64 : (1ULL << width) - 1;

	if (starts(NAME, "bstrpick")) {
		if (size == 8 && lsb == 0 && (width == 8 || width == 16 || width == 32)) {
			set(il, rd, il_zx(il, 8, rn(il, rj, width / 8)));
			return;
		}
		E v = rn(il, rj, size);
		if (lsb)
			v = il_lsr(il, size, v, il_const(il, 1, (uint64_t)lsb));
		if ((uint64_t)msb != size * 8 - 1)
			v = il_and(il, size, v, il_const(il, size, field));
		if (size == 4)
			setw(il, rd, v);
		else
			set(il, rd, v);
		return;
	}

	uint64_t mask = field << lsb;
	E src = rn(il, rj, size);
	if (lsb)
		src = il_lsl(il, size, src, il_const(il, 1, (uint64_t)lsb));
	E v = il_or(il, size,
	            il_and(il, size, rn(il, rd, size), il_const(il, size, ~mask & full)),
	            il_and(il, size, src, il_const(il, size, mask)));
	if (size == 4)
		setw(il, rd, v);
	else
		set(il, rd, v);
}

static void lift_mulx(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1), rk = R(2);
	const char *n = NAME;
	if (!strcmp(n, "mulh.d") || !strcmp(n, "mulh.du")) {
		bool s = !strcmp(n, "mulh.d");
		BNLowLevelILOperation ext = s ? LLIL_SX : LLIL_ZX;
		BNLowLevelILOperation shr = s ? LLIL_ASR : LLIL_LSR;
		E prod = il_mul(il, 16, il_un(il, ext, 16, r(il, rj)), il_un(il, ext, 16, r(il, rk)));
		set(il, rd, il_low(il, 8, il_bin(il, shr, 16, prod, il_const(il, 1, 64))));
		return;
	}
	bool is_signed = !strcmp(n, "mulh.w") || !strcmp(n, "mulw.d.w");
	BNLowLevelILOperation ext = is_signed ? LLIL_SX : LLIL_ZX;
	E prod = il_mul(il, 8, il_un(il, ext, 8, r32(il, rj)), il_un(il, ext, 8, r32(il, rk)));
	if (starts(n, "mulw"))
		set(il, rd, prod);
	else if (is_signed)
		set(il, rd, il_asr(il, 8, prod, il_const(il, 1, 32)));
	else
		setw(il, rd, il_low(il, 4, il_lsr(il, 8, prod, il_const(il, 1, 32))));
}

static size_t suffix_size(const char *name, bool *is_unsigned)
{
	const char *s = strchr(name, '.');
	s = s ? s + 1 : "";
	size_t len = strcspn(s, ".");
	if (is_unsigned)
		*is_unsigned = len > 0 && s[len - 1] == 'u';
	switch (s[0]) {
	case 'b': return 1;
	case 'h': return 2;
	case 'w': return 4;
	default:  return 8;
	}
}

static const char *const BOUNDED[] = { "ldgt", "ldle", "stgt", "stle", "fldgt", "fldle", "fstgt", "fstle" };

static E mem_addr(BNLowLevelILFunction *il, const la_insn *insn)
{
	unsigned base = R(1);
	bool bounded = false;
	for (size_t i = 0; i < sizeof(BOUNDED) / sizeof(BOUNDED[0]); i++)
		bounded |= starts(NAME, BOUNDED[i]);
	if (insn->nops == 2 || bounded)
		return r(il, base);
	if (insn->ops[2].slot == LA_S_RK)
		return il_add(il, 8, r(il, base), r(il, R(2)));
	if (base == 0)
		return il_const_ptr(il, 8, (uint64_t)V(2));
	if (V(2) == 0)
		return r(il, base);
	return il_add(il, 8, r(il, base), il_const(il, 8, (uint64_t)V(2)));
}

static void lift_load(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	bool u;
	size_t size = suffix_size(NAME, &u);
	E v = il_load(il, size, mem_addr(il, insn));
	if (size != 8)
		v = u ? il_zx(il, 8, v) : il_sx(il, 8, v);
	set(il, R(0), v);
}

static void lift_store(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	size_t size = suffix_size(NAME, NULL);
	unsigned rd = R(0);
	il_append(il, il_store(il, size, mem_addr(il, insn), rn(il, rd, size)));
	if (starts(NAME, "sc.") || starts(NAME, "screl."))
		set(il, rd, il_const(il, 8, 1));
}

static void lift_amo(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rk = R(1), rj = R(2);
	const char *op_name = NAME + 2;
	size_t size = suffix_size(NAME, NULL);
	uint32_t old = LLIL_TEMP(0);
	il_append(il, il_set_reg(il, size, old, il_load(il, size, r(il, rj))));
	E nw;
	if (starts(op_name, "swap"))
		nw = rn(il, rk, size);
	else {
		BNLowLevelILOperation op = starts(op_name, "add") ? LLIL_ADD
		                         : starts(op_name, "and") ? LLIL_AND
		                         : starts(op_name, "or")  ? LLIL_OR : LLIL_XOR;
		nw = il_bin(il, op, size, il_reg(il, size, old), rn(il, rk, size));
	}
	il_append(il, il_store(il, size, r(il, rj), nw));
	if (rd != 0) {
		E v = il_reg(il, size, old);
		set(il, rd, size == 8 ? v : il_sx(il, 8, v));
	}
}

static void lift_prefetch(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	(void)insn;
	il_append(il, il_nop(il));
}

static void cond_branch(BNArchitecture *arch, BNLowLevelILFunction *il, E cond, uint64_t target, uint64_t fallthrough)
{
	BNLowLevelILLabel tl, fl;
	BNLowLevelILLabel *t = BNGetLowLevelILLabelForAddress(il, arch, target);
	BNLowLevelILLabel *fal = BNGetLowLevelILLabelForAddress(il, arch, fallthrough);
	bool new_t = t == NULL, new_f = fal == NULL;
	if (new_t) {
		BNLowLevelILInitLabel(&tl);
		t = &tl;
	}
	if (new_f) {
		BNLowLevelILInitLabel(&fl);
		fal = &fl;
	}
	il_append(il, BNLowLevelILIf(il, cond, t, fal));
	if (new_t) {
		BNLowLevelILMarkLabel(il, t);
		il_append(il, il_jump(il, il_const_ptr(il, 8, target)));
	}
	if (new_f)
		BNLowLevelILMarkLabel(il, fal);
}

static void lift_bcc(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	static const struct { const char *name; BNLowLevelILOperation op; } BCOND[] = {
		{ "beq", LLIL_CMP_E },    { "bne", LLIL_CMP_NE },
		{ "blt", LLIL_CMP_SLT },  { "bge", LLIL_CMP_SGE },
		{ "bltu", LLIL_CMP_ULT }, { "bgeu", LLIL_CMP_UGE },
	};
	unsigned rj = R(0), rd = R(1);
	size_t i = 0;
	while (strcmp(BCOND[i].name, NAME))
		i++;
	E cond = il_bin(il, BCOND[i].op, 8, r(il, rj), r(il, rd));
	cond_branch(arch, il, cond, (uint64_t)V(2), insn->addr + 4);
}

static void lift_bccz(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	BNLowLevelILOperation op = !strcmp(NAME, "beqz") ? LLIL_CMP_E : LLIL_CMP_NE;
	cond_branch(arch, il, il_bin(il, op, 8, r(il, R(0)), il_const(il, 8, 0)), (uint64_t)V(1), insn->addr + 4);
}

static void lift_bcfp(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	BNLowLevelILOperation op = !strcmp(NAME, "bceqz") ? LLIL_CMP_E : LLIL_CMP_NE;
	E cond = il_bin(il, op, 1, il_reg(il, 1, LA_REG_FCC(R(0))), il_const(il, 1, 0));
	cond_branch(arch, il, cond, (uint64_t)V(1), insn->addr + 4);
}

static void lift_b(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	uint64_t target = (uint64_t)V(0);
	BNLowLevelILLabel *label = BNGetLowLevelILLabelForAddress(il, arch, target);
	if (label)
		il_append(il, BNLowLevelILGoto(il, label));
	else
		il_append(il, il_jump(il, il_const_ptr(il, 8, target)));
}

static void lift_bl(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	il_append(il, il_call(il, il_const_ptr(il, 8, (uint64_t)V(0))));
}

static void lift_jirl(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned rd = R(0), rj = R(1);
	int64_t off = V(2);
	E dest = off == 0 ? r(il, rj) : il_add(il, 8, r(il, rj), il_const(il, 8, (uint64_t)off));
	if (rd == 1) {
		il_append(il, il_call(il, dest));
	} else if (rd == 0) {
		if (rj == 1 && off == 0)
			il_append(il, il_ret(il, dest));
		else
			il_append(il, il_jump(il, dest));
	} else {
		uint32_t tmp = LLIL_TEMP(0);
		il_append(il, il_set_reg(il, 8, tmp, dest));
		il_append(il, il_set_reg(il, 8, LA_REG_GPR(rd), il_const_ptr(il, 8, insn->addr + 4)));
		il_append(il, il_jump(il, il_reg(il, 8, tmp)));
	}
}

static void lift_syscall(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	(void)insn;
	il_append(il, il_system_call(il));
}

static void lift_break(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	int64_t code = V(0);
	if (code == 0 || code == 6 || code == 7)
		il_append(il, il_trap(il, (uint64_t)code));
	else
		lift_intrinsic(arch, insn, il);
}

static void lift_ertn(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	lift_intrinsic(arch, insn, il);
	il_append(il, il_no_ret(il));
}

static void lift_fload(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	size_t size = fsize(NAME);
	fset(il, R(0), size, il_load(il, size, mem_addr(il, insn)));
}

static void lift_fstore(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	size_t size = fsize(NAME);
	il_append(il, il_store(il, size, mem_addr(il, insn), f(il, R(0), size)));
}

static void lift_farith(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	size_t size = fsize(NAME);
	BNLowLevelILOperation op = starts(NAME, "fadd.") ? LLIL_FADD
	                         : starts(NAME, "fsub.") ? LLIL_FSUB
	                         : starts(NAME, "fmul.") ? LLIL_FMUL : LLIL_FDIV;
	fset(il, R(0), size, il_bin(il, op, size, f(il, R(1), size), f(il, R(2), size)));
}

static void lift_fma(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	size_t size = fsize(NAME);
	char base[16];
	size_t blen = strcspn(NAME, ".");
	memcpy(base, NAME, blen);
	base[blen] = '\0';
	E prod = il_bin(il, LLIL_FMUL, size, f(il, R(1), size), f(il, R(2), size));
	BNLowLevelILOperation op = ends(base, "madd") ? LLIL_FADD : LLIL_FSUB;
	E v = il_bin(il, op, size, prod, f(il, R(3), size));
	if (starts(base, "fnm"))
		v = il_un(il, LLIL_FNEG, size, v);
	fset(il, R(0), size, v);
}

static void lift_funary(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	size_t size = fsize(NAME);
	const char *n = NAME;
	E src = f(il, R(1), size);
	E v;
	if (starts(n, "fabs."))
		v = il_un(il, LLIL_FABS, size, src);
	else if (starts(n, "fneg."))
		v = il_un(il, LLIL_FNEG, size, src);
	else if (starts(n, "fsqrt."))
		v = il_un(il, LLIL_FSQRT, size, src);
	else if (starts(n, "fmov."))
		v = src;
	else if (starts(n, "frecip."))
		v = il_bin(il, LLIL_FDIV, size, il_float_one(il, size), src);
	else if (starts(n, "frsqrt."))
		v = il_bin(il, LLIL_FDIV, size, il_float_one(il, size), il_un(il, LLIL_FSQRT, size, src));
	else
		v = il_un(il, LLIL_ROUND_TO_INT, size, src);
	fset(il, R(0), size, v);
}

static void lift_fmoves(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned d = R(0), s = R(1);
	const char *n = NAME;
	if (!strcmp(n, "movgr2fr.w")) {
		fset(il, d, 4, r32(il, s));
	} else if (!strcmp(n, "movgr2fr.d")) {
		fset(il, d, 8, r(il, s));
	} else if (!strcmp(n, "movgr2frh.w")) {
		E hi = il_lsl(il, 8, il_zx(il, 8, r32(il, s)), il_const(il, 1, 32));
		fset(il, d, 8, il_or(il, 8, hi, il_zx(il, 8, f(il, d, 4))));
	} else if (!strcmp(n, "movfr2gr.s")) {
		set(il, d, il_sx(il, 8, f(il, s, 4)));
	} else if (!strcmp(n, "movfr2gr.d")) {
		set(il, d, f(il, s, 8));
	} else if (!strcmp(n, "movfrh2gr.s")) {
		setw(il, d, il_low(il, 4, il_lsr(il, 8, f(il, s, 8), il_const(il, 1, 32))));
	} else if (!strcmp(n, "movgr2fcsr")) {
		il_append(il, il_set_reg(il, 4, LA_REG_FCSR(d), r32(il, s)));
	} else if (!strcmp(n, "movfcsr2gr")) {
		set(il, d, il_sx(il, 8, il_reg(il, 4, LA_REG_FCSR(s))));
	} else if (!strcmp(n, "movfr2cf")) {
		il_append(il, il_set_reg(il, 1, LA_REG_FCC(d),
		                         il_and(il, 1, il_low(il, 1, f(il, s, 8)), il_const(il, 1, 1))));
	} else if (!strcmp(n, "movgr2cf")) {
		il_append(il, il_set_reg(il, 1, LA_REG_FCC(d), il_and(il, 1, rn(il, s, 1), il_const(il, 1, 1))));
	} else if (!strcmp(n, "movcf2fr")) {
		fset(il, d, 8, il_zx(il, 8, il_reg(il, 1, LA_REG_FCC(s))));
	} else {
		set(il, d, il_zx(il, 8, il_reg(il, 1, LA_REG_FCC(s))));
	}
}

static void lift_fconv(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	const char *p = strchr(NAME, '.');
	char dst_t = p[1], src_t = p[3];
	size_t dsize = (dst_t == 's' || dst_t == 'w') ? 4 : 8;
	size_t ssize = (src_t == 's' || src_t == 'w') ? 4 : 8;
	E src = f(il, R(1), ssize);
	if (starts(NAME, "fcvt"))
		fset(il, R(0), dsize, il_un(il, LLIL_FLOAT_CONV, dsize, src));
	else
		fset(il, R(0), dsize, il_un(il, LLIL_INT_TO_FLOAT, dsize, src));
}

static bool match_ftint(const char *n, int *mode, char *dst_t, char *src_t)
{
	if (!starts(n, "ftint"))
		return false;
	const char *p = n + 5;
	static const char *const modes[] = { "rm.", "rp.", "rz.", "rne." };
	*mode = 0;
	for (int i = 0; i < 4; i++)
		if (starts(p, modes[i])) {
			*mode = i + 1;
			p += strlen(modes[i]) - 1;
			break;
		}
	if (p[0] != '.' || (p[1] != 'w' && p[1] != 'l') || p[2] != '.' || (p[3] != 's' && p[3] != 'd') || p[4])
		return false;
	*dst_t = p[1];
	*src_t = p[3];
	return true;
}

static void lift_ftint(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	int mode;
	char dst_t, src_t;
	match_ftint(NAME, &mode, &dst_t, &src_t);
	size_t ssize = src_t == 's' ? 4 : 8;
	size_t dsize = dst_t == 'w' ? 4 : 8;
	E src = f(il, R(1), ssize);
	if (mode == 1)
		src = il_un(il, LLIL_FLOOR, ssize, src);
	else if (mode == 2)
		src = il_un(il, LLIL_CEIL, ssize, src);
	else if (mode != 3)
		src = il_un(il, LLIL_ROUND_TO_INT, ssize, src);
	fset(il, R(0), dsize, il_un(il, LLIL_FLOAT_TO_INT, dsize, src));
}

static bool match_fcmp(const char *n, char *cond, size_t cap, char *fmt)
{
	if (!starts(n, "fcmp.") || (n[5] != 'c' && n[5] != 's'))
		return false;
	const char *c = n + 6;
	size_t len = 0;
	while ((c[len] >= 'a' && c[len] <= 'z') || (c[len] >= 'A' && c[len] <= 'Z') ||
	       (c[len] >= '0' && c[len] <= '9') || c[len] == '_')
		len++;
	if (len == 0 || len >= cap || c[len] != '.' || (c[len + 1] != 's' && c[len + 1] != 'd') || c[len + 2])
		return false;
	memcpy(cond, c, len);
	cond[len] = '\0';
	*fmt = c[len + 1];
	return true;
}

static E fcmp_cmp(BNLowLevelILFunction *il, BNLowLevelILOperation op, size_t size, unsigned fj, unsigned fk)
{
	return il_b2i(il, 1, il_bin(il, op, size, f(il, fj, size), f(il, fk, size)));
}

static E fcmp_inv(BNLowLevelILFunction *il, BNLowLevelILOperation op, size_t size, unsigned fj, unsigned fk)
{
	return il_xor(il, 1, fcmp_cmp(il, op, size, fj, fk), il_const(il, 1, 1));
}

static void lift_fcmp(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned cd = R(0), fj = R(1), fk = R(2);
	char cond[16], fmt;
	match_fcmp(NAME, cond, sizeof(cond), &fmt);
	size_t size = fmt == 's' ? 4 : 8;
	E v;
	if (!strcmp(cond, "af"))
		v = il_const(il, 1, 0);
	else if (!strcmp(cond, "lt"))
		v = fcmp_cmp(il, LLIL_FCMP_LT, size, fj, fk);
	else if (!strcmp(cond, "eq"))
		v = fcmp_cmp(il, LLIL_FCMP_E, size, fj, fk);
	else if (!strcmp(cond, "le"))
		v = fcmp_cmp(il, LLIL_FCMP_LE, size, fj, fk);
	else if (!strcmp(cond, "un"))
		v = fcmp_cmp(il, LLIL_FCMP_UO, size, fj, fk);
	else if (!strcmp(cond, "or"))
		v = fcmp_cmp(il, LLIL_FCMP_O, size, fj, fk);
	else if (!strcmp(cond, "ult"))
		v = fcmp_inv(il, LLIL_FCMP_GE, size, fj, fk);
	else if (!strcmp(cond, "ule"))
		v = fcmp_inv(il, LLIL_FCMP_GT, size, fj, fk);
	else if (!strcmp(cond, "une"))
		v = fcmp_cmp(il, LLIL_FCMP_NE, size, fj, fk);
	else if (!strcmp(cond, "ueq"))
		v = il_or(il, 1, fcmp_cmp(il, LLIL_FCMP_E, size, fj, fk), fcmp_cmp(il, LLIL_FCMP_UO, size, fj, fk));
	else if (!strcmp(cond, "ne"))
		v = il_or(il, 1, fcmp_cmp(il, LLIL_FCMP_LT, size, fj, fk), fcmp_cmp(il, LLIL_FCMP_GT, size, fj, fk));
	else {
		il_append(il, il_undefined(il));
		return;
	}
	il_append(il, il_set_reg(il, 1, LA_REG_FCC(cd), v));
}

static void lift_fsel(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	unsigned fd = R(0), fj = R(1), fk = R(2), ca = R(3);
	BNLowLevelILLabel t, fl, done;
	BNLowLevelILInitLabel(&t);
	BNLowLevelILInitLabel(&fl);
	BNLowLevelILInitLabel(&done);
	E cond = il_bin(il, LLIL_CMP_NE, 1, il_reg(il, 1, LA_REG_FCC(ca)), il_const(il, 1, 0));
	il_append(il, BNLowLevelILIf(il, cond, &t, &fl));
	BNLowLevelILMarkLabel(il, &t);
	fset(il, fd, 8, f(il, fk, 8));
	il_append(il, BNLowLevelILGoto(il, &done));
	BNLowLevelILMarkLabel(il, &fl);
	fset(il, fd, 8, f(il, fj, 8));
	il_append(il, BNLowLevelILGoto(il, &done));
	BNLowLevelILMarkLabel(il, &done);
}

static void lift_vload(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	bool x = NAME[0] == 'x';
	size_t size = x ? 32 : 16;
	uint32_t reg = x ? LA_REG_XR(R(0)) : LA_REG_VR(R(0));
	il_append(il, il_set_reg(il, size, reg, il_load(il, size, mem_addr(il, insn))));
}

static void lift_vstore(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	bool x = NAME[0] == 'x';
	size_t size = x ? 32 : 16;
	uint32_t reg = x ? LA_REG_XR(R(0)) : LA_REG_VR(R(0));
	il_append(il, il_store(il, size, mem_addr(il, insn), il_reg(il, size, reg)));
}

static void lift_vrepli(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	if (V(1) != 0) {
		lift_intrinsic(arch, insn, il);
		return;
	}
	bool x = NAME[0] == 'x';
	size_t size = x ? 32 : 16;
	uint32_t reg = x ? LA_REG_XR(R(0)) : LA_REG_VR(R(0));
	il_append(il, il_set_reg(il, size, reg, il_const(il, size, 0)));
}

typedef struct {
	uint16_t intrinsic;
	uint8_t nout, nin;
	uint8_t out[2];
	uint8_t in[LA_MAX_OPS];
	uint8_t size[LA_MAX_OPS];
} op_sig;

typedef struct {
	char *name;
	uint8_t nin, nout;
	uint8_t in_size[LA_MAX_OPS];
	uint8_t out_size[2];
} intrinsic_info;

static op_sig *g_sig;
static intrinsic_info *g_intr;
static unsigned g_intr_count;
static lift_fn *g_lifters;
static const char **g_lifter_names;

static bool rlra_ni(const char *p)
{
	if (!starts(p, "rl") && !starts(p, "ra"))
		return false;
	p += 2;
	if (*p == 'r' && starts(p + 1, "ni."))
		return true;
	return starts(p, "ni.");
}

static bool reads_dest(const char *m)
{
	const char *p = m[0] == 'x' ? m + 1 : m;
	if (p[0] == 'v') {
		static const char *const alt[] = {
			"madd", "msub", "shuf.h", "shuf.w", "shuf.d", "shuf4i.d", "permi.w", "permi.q",
			"extrins", "bitseli", "insgr2vr", "frstp",
		};
		for (size_t i = 0; i < sizeof(alt) / sizeof(alt[0]); i++)
			if (starts(p + 1, alt[i]))
				return true;
		if (p[1] == 's' && ((p[2] == 's' && rlra_ni(p + 3)) || rlra_ni(p + 2)))
			return true;
	}
	return starts(m, "xvinsve0") || starts(m, "csrwr") || starts(m, "csrxchg") ||
	       starts(m, "gcsrwr") || starts(m, "gcsrxchg") || starts(m, "x86settag");
}

static uint8_t operand_size(const char *mnemonic, uint8_t slot)
{
	switch (slot) {
	case LA_S_FD: case LA_S_FJ: case LA_S_FK: case LA_S_FA:
		return (uint8_t)fsize(mnemonic);
	case LA_S_VD: case LA_S_VJ: case LA_S_VK: case LA_S_VA:
		return 16;
	case LA_S_XD: case LA_S_XJ: case LA_S_XK: case LA_S_XA:
		return 32;
	case LA_S_CD: case LA_S_CJ: case LA_S_CA:
		return 1;
	case LA_S_FCSRD: case LA_S_FCSRJ:
		return 4;
	default:
		return 8;
	}
}

static void signature(unsigned idx, op_sig *s)
{
	const char *m = la_opcodes[idx].name;
	const la_opinfo *info = &la_info[idx];
	memset(s, 0, sizeof(*s));
	for (unsigned i = 0; i < info->nops; i++)
		s->size[i] = operand_size(m, la_specs[info->spec[i]].slot);

	if (!strcmp(m, "rdtimel.w") || !strcmp(m, "rdtimeh.w") || !strcmp(m, "rdtime.d")) {
		s->nout = 2;
		s->out[0] = 0;
		s->out[1] = 1;
		return;
	}
	uint8_t slot0 = info->nops ? la_specs[info->spec[0]].slot : LA_S_NONE;
	bool dest = slot0 == LA_S_RD || slot0 == LA_S_FD || slot0 == LA_S_VD || slot0 == LA_S_XD ||
	            slot0 == LA_S_CD || slot0 == LA_S_FCSRD || slot0 == LA_S_SCRD;
	bool store_like = starts(m, "st") || starts(m, "fst") || starts(m, "vst") ||
	                  starts(m, "xvst") || starts(m, "iocsrwr");
	if (dest && !store_like) {
		s->nout = 1;
		s->out[0] = 0;
		if (reads_dest(m))
			s->in[s->nin++] = 0;
		for (unsigned i = 1; i < info->nops; i++)
			s->in[s->nin++] = (uint8_t)i;
		return;
	}
	for (unsigned i = 0; i < info->nops; i++)
		s->in[s->nin++] = (uint8_t)i;
}

static uint32_t reg_for(const la_operand *op, size_t size)
{
	unsigned v = (unsigned)op->value;
	switch (op->type) {
	case LA_T_FPR:  return fpr_name(v, size);
	case LA_T_VR:   return LA_REG_VR(v);
	case LA_T_XR:   return LA_REG_XR(v);
	case LA_T_FCC:  return LA_REG_FCC(v);
	case LA_T_FCSR: return LA_REG_FCSR(v);
	case LA_T_SCR:  return LA_REG_SCR(v);
	default:        return LA_REG_GPR(v);
	}
}

static void lift_intrinsic(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	(void)arch;
	const op_sig *s = &g_sig[insn->index];
	uint64_t outputs[2], params[LA_MAX_OPS];

	for (unsigned k = 0; k < s->nout; k++) {
		unsigned i = s->out[k];
		const la_operand *op = &insn->ops[i];
		if (op->type == LA_T_GPR && op->value == 0)
			outputs[k] = LLIL_TEMP(i);
		else
			outputs[k] = reg_for(op, s->size[i]);
	}
	for (unsigned k = 0; k < s->nin; k++) {
		unsigned i = s->in[k];
		const la_operand *op = &insn->ops[i];
		size_t size = s->size[i];
		if (op->type == LA_T_GPR)
			params[k] = r(il, (unsigned)op->value);
		else if (op->type == LA_T_IMM || op->type == LA_T_UIMM)
			params[k] = il_const(il, 8, (uint64_t)op->value);
		else if (op->type == LA_T_ADDR)
			params[k] = il_const_ptr(il, 8, (uint64_t)op->value);
		else
			params[k] = il_reg(il, size, reg_for(op, size));
	}
	E call_param = ex(il, LLIL_CALL_PARAM, 0, s->nin, BNLowLevelILAddOperandList(il, params, s->nin), 0, 0);
	il_append(il, ex(il, LLIL_INTRINSIC, 0, s->nout, BNLowLevelILAddOperandList(il, outputs, s->nout),
	                 s->intrinsic, call_param));
}

unsigned la_intrinsic_count(void) { return g_intr_count; }

const char *la_intrinsic_name(unsigned idx) { return idx < g_intr_count ? g_intr[idx].name : NULL; }

unsigned la_intrinsic_inputs(unsigned idx, const uint8_t **sizes)
{
	if (idx >= g_intr_count)
		return 0;
	*sizes = g_intr[idx].in_size;
	return g_intr[idx].nin;
}

unsigned la_intrinsic_outputs(unsigned idx, const uint8_t **sizes)
{
	if (idx >= g_intr_count)
		return 0;
	*sizes = g_intr[idx].out_size;
	return g_intr[idx].nout;
}

static const struct { const char *fn_name; lift_fn fn; const char *names[40]; } LIFTERS[] = {
	{ "lift_op3", lift_op3, { "add.w", "add.d", "sub.w", "sub.d", "and", "or", "xor", "mul.w", "mul.d",
	                          "div.w", "div.d", "div.wu", "div.du", "mod.w", "mod.d", "mod.wu", "mod.du" } },
	{ "lift_op3_not", lift_op3_not, { "nor", "andn", "orn" } },
	{ "lift_slt", lift_slt, { "slt", "sltu", "slti", "sltui" } },
	{ "lift_mask", lift_mask, { "maskeqz", "masknez" } },
	{ "lift_addi_w", lift_addi_w, { "addi.w" } },
	{ "lift_addi_d", lift_addi_d, { "addi.d", "addu16i.d" } },
	{ "lift_logic_imm", lift_logic_imm, { "andi", "ori", "xori" } },
	{ "lift_lu12i", lift_lu12i, { "lu12i.w" } },
	{ "lift_lu32i", lift_lu32i, { "lu32i.d" } },
	{ "lift_lu52i", lift_lu52i, { "lu52i.d" } },
	{ "lift_pcrel", lift_pcrel, { "pcaddi", "pcaddu12i", "pcaddu18i", "pcalau12i" } },
	{ "lift_shift_reg", lift_shift_reg, { "sll.w", "srl.w", "sra.w", "rotr.w", "sll.d", "srl.d", "sra.d", "rotr.d" } },
	{ "lift_shift_imm", lift_shift_imm, { "slli.w", "srli.w", "srai.w", "rotri.w",
	                                      "slli.d", "srli.d", "srai.d", "rotri.d" } },
	{ "lift_alsl", lift_alsl, { "alsl.w", "alsl.wu", "alsl.d" } },
	{ "lift_bytepick", lift_bytepick, { "bytepick.w", "bytepick.d" } },
	{ "lift_ext", lift_ext, { "ext.w.b", "ext.w.h" } },
	{ "lift_bstr", lift_bstr, { "bstrins.w", "bstrins.d", "bstrpick.w", "bstrpick.d" } },
	{ "lift_mulx", lift_mulx, { "mulh.w", "mulh.wu", "mulw.d.w", "mulw.d.wu", "mulh.d", "mulh.du" } },
	{ "lift_load", lift_load, { "ld.b", "ld.h", "ld.w", "ld.d", "ld.bu", "ld.hu", "ld.wu",
	                            "ldx.b", "ldx.h", "ldx.w", "ldx.d", "ldx.bu", "ldx.hu", "ldx.wu",
	                            "ldgt.b", "ldgt.h", "ldgt.w", "ldgt.d", "ldle.b", "ldle.h", "ldle.w", "ldle.d",
	                            "ldptr.w", "ldptr.d", "ll.w", "ll.d", "llacq.w", "llacq.d" } },
	{ "lift_store", lift_store, { "st.b", "st.h", "st.w", "st.d", "stx.b", "stx.h", "stx.w", "stx.d",
	                              "stgt.b", "stgt.h", "stgt.w", "stgt.d", "stle.b", "stle.h", "stle.w", "stle.d",
	                              "stptr.w", "stptr.d", "sc.w", "sc.d", "screl.w", "screl.d" } },
	{ "lift_amo", lift_amo, {
		"amswap.b", "amswap.h", "amswap.w", "amswap.d", "amswap_db.b", "amswap_db.h", "amswap_db.w", "amswap_db.d",
		"amadd.b", "amadd.h", "amadd.w", "amadd.d", "amadd_db.b", "amadd_db.h", "amadd_db.w", "amadd_db.d",
		"amand.b", "amand.h", "amand.w", "amand.d", "amand_db.b", "amand_db.h", "amand_db.w", "amand_db.d",
		"amor.b", "amor.h", "amor.w", "amor.d", "amor_db.b", "amor_db.h", "amor_db.w", "amor_db.d",
		"amxor.b", "amxor.h", "amxor.w", "amxor.d", "amxor_db.b", "amxor_db.h", "amxor_db.w", "amxor_db.d" } },
	{ "lift_prefetch", lift_prefetch, { "preld", "preldx" } },
	{ "lift_bcc", lift_bcc, { "beq", "bne", "blt", "bge", "bltu", "bgeu" } },
	{ "lift_bccz", lift_bccz, { "beqz", "bnez" } },
	{ "lift_bcfp", lift_bcfp, { "bceqz", "bcnez" } },
	{ "lift_b", lift_b, { "b" } },
	{ "lift_bl", lift_bl, { "bl" } },
	{ "lift_jirl", lift_jirl, { "jirl" } },
	{ "lift_syscall", lift_syscall, { "syscall" } },
	{ "lift_break", lift_break, { "break" } },
	{ "lift_ertn", lift_ertn, { "ertn" } },
	{ "lift_fload", lift_fload, { "fld.s", "fld.d", "fldx.s", "fldx.d", "fldgt.s", "fldgt.d", "fldle.s", "fldle.d" } },
	{ "lift_fstore", lift_fstore, { "fst.s", "fst.d", "fstx.s", "fstx.d", "fstgt.s", "fstgt.d", "fstle.s", "fstle.d" } },
	{ "lift_farith", lift_farith, { "fadd.s", "fadd.d", "fsub.s", "fsub.d", "fmul.s", "fmul.d", "fdiv.s", "fdiv.d" } },
	{ "lift_fma", lift_fma, { "fmadd.s", "fmadd.d", "fmsub.s", "fmsub.d", "fnmadd.s", "fnmadd.d", "fnmsub.s", "fnmsub.d" } },
	{ "lift_funary", lift_funary, { "fabs.s", "fabs.d", "fneg.s", "fneg.d", "fsqrt.s", "fsqrt.d", "fmov.s", "fmov.d",
	                                "frecip.s", "frecip.d", "frsqrt.s", "frsqrt.d", "frint.s", "frint.d" } },
	{ "lift_fmoves", lift_fmoves, { "movgr2fr.w", "movgr2fr.d", "movgr2frh.w", "movfr2gr.s", "movfr2gr.d",
	                                "movfrh2gr.s", "movgr2fcsr", "movfcsr2gr", "movfr2cf", "movcf2fr",
	                                "movgr2cf", "movcf2gr" } },
	{ "lift_fconv", lift_fconv, { "fcvt.s.d", "fcvt.d.s", "ffint.s.w", "ffint.s.l", "ffint.d.w", "ffint.d.l" } },
	{ "lift_fsel", lift_fsel, { "fsel" } },
	{ "lift_vload", lift_vload, { "vld", "vldx", "xvld", "xvldx" } },
	{ "lift_vstore", lift_vstore, { "vst", "vstx", "xvst", "xvstx" } },
	{ "lift_vrepli", lift_vrepli, { "vrepli.b", "vrepli.h", "vrepli.w", "vrepli.d",
	                                "xvrepli.b", "xvrepli.h", "xvrepli.w", "xvrepli.d" } },
};

static void pick_lifter(const char *name, lift_fn *fn, const char **fn_name)
{
	int mode;
	char a, b, cond[16];
	if (match_ftint(name, &mode, &a, &b)) {
		*fn = lift_ftint;
		*fn_name = "lift_ftint";
		return;
	}
	if (match_fcmp(name, cond, sizeof(cond), &a)) {
		*fn = lift_fcmp;
		*fn_name = "lift_fcmp";
		return;
	}
	for (size_t i = 0; i < sizeof(LIFTERS) / sizeof(LIFTERS[0]); i++)
		for (size_t k = 0; k < 40 && LIFTERS[i].names[k]; k++)
			if (!strcmp(LIFTERS[i].names[k], name)) {
				*fn = LIFTERS[i].fn;
				*fn_name = LIFTERS[i].fn_name;
				return;
			}
	*fn = lift_intrinsic;
	*fn_name = "lift_intrinsic";
}

bool la_lift_init(void)
{
	unsigned n = la_opcode_count;
	g_sig = calloc(n, sizeof(*g_sig));
	g_intr = calloc(n, sizeof(*g_intr));
	g_lifters = calloc(n, sizeof(*g_lifters));
	g_lifter_names = calloc(n, sizeof(*g_lifter_names));
	if (!g_sig || !g_intr || !g_lifters || !g_lifter_names)
		return false;

	for (unsigned i = 0; i < n; i++) {
		pick_lifter(la_opcodes[i].name, &g_lifters[i], &g_lifter_names[i]);
		signature(i, &g_sig[i]);

		const char *m = la_opcodes[i].name;
		size_t len = strlen(m);
		char *name = malloc(len + 3);
		if (!name)
			return false;
		name[0] = name[1] = '_';
		for (size_t k = 0; k <= len; k++)
			name[k + 2] = m[k] == '.' ? '_' : m[k];

		unsigned idx = g_intr_count;
		for (unsigned k = 0; k < g_intr_count; k++)
			if (!strcmp(g_intr[k].name, name)) {
				idx = k;
				break;
			}
		if (idx == g_intr_count) {
			intrinsic_info *t = &g_intr[g_intr_count++];
			t->name = name;
			t->nin = g_sig[i].nin;
			t->nout = g_sig[i].nout;
			for (unsigned k = 0; k < t->nin; k++)
				t->in_size[k] = g_sig[i].size[g_sig[i].in[k]];
			for (unsigned k = 0; k < t->nout; k++)
				t->out_size[k] = g_sig[i].size[g_sig[i].out[k]];
		} else {
			free(name);
		}
		g_sig[i].intrinsic = (uint16_t)idx;
	}
	return true;
}

void la_lift(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il)
{
	g_lifters[insn->index](arch, insn, il);
}

const char *la_lifter_name(unsigned opcode_index)
{
	return opcode_index < la_opcode_count ? g_lifter_names[opcode_index] : NULL;
}
