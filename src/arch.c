#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "la64_bn.h"

#if BN_CURRENT_CORE_ABI_VERSION != 147 && BN_CURRENT_CORE_ABI_VERSION != 164 && \
    BN_CURRENT_CORE_ABI_VERSION != 187 && !defined(LA_ALLOW_UNTESTED_API)
#error "Untested binaryninjacore.h version: check BNCustomArchitecture/BNCustomCallingConvention for new fields, then build with -DLA_ALLOW_UNTESTED_API"
#endif

#define SHOW_ALIASES   1
#define MNEMONIC_WIDTH 12

static BNArchitecture *g_arch;

enum { K_OTHER, K_COND, K_B, K_BL, K_JIRL, K_BREAK, K_ERTN };
static uint8_t *g_kind;
static uint8_t *g_pcrel;

static char g_reg_name[LA_REG_COUNT][16];
static BNRegisterInfo g_reg_info[LA_REG_COUNT];
static BNType *g_int_type[33];

static void def_reg(uint32_t id, const char *name, uint32_t full, size_t size)
{
	snprintf(g_reg_name[id], sizeof(g_reg_name[id]), "%s", name);
	g_reg_info[id].fullWidthRegister = full;
	g_reg_info[id].offset = 0;
	g_reg_info[id].size = size;
	g_reg_info[id].extend = NoExtend;
}

bool la_arch_init_tables(void)
{
	char buf[16];
	for (uint32_t i = 0; i < 32; i++)
		def_reg(LA_REG_GPR(i), la_reg_name(LA_T_GPR, i), LA_REG_GPR(i), 8);
	for (uint32_t i = 0; i < 32; i++) {
		uint32_t xr = LA_REG_XR(i);
		def_reg(xr, la_reg_name(LA_T_XR, i), xr, 32);
		def_reg(LA_REG_VR(i), la_reg_name(LA_T_VR, i), xr, 16);
		def_reg(LA_REG_FPR(i), la_reg_name(LA_T_FPR, i), xr, 8);
		snprintf(buf, sizeof(buf), "%s_s", la_reg_name(LA_T_FPR, i));
		def_reg(LA_REG_FPRS(i), buf, xr, 4);
	}
	for (uint32_t i = 0; i < 8; i++)
		def_reg(LA_REG_FCC(i), la_reg_name(LA_T_FCC, i), LA_REG_FCC(i), 1);
	for (uint32_t i = 0; i < 4; i++) {
		def_reg(LA_REG_FCSR(i), la_reg_name(LA_T_FCSR, i), LA_REG_FCSR(i), 4);
		def_reg(LA_REG_SCR(i), la_reg_name(LA_T_SCR, i), LA_REG_SCR(i), 8);
	}
	def_reg(LA_REG_EFLAGS, "eflags", LA_REG_EFLAGS, 4);
	def_reg(LA_REG_FTOP, "ftop", LA_REG_FTOP, 4);
	def_reg(LA_REG_PC, "$pc", LA_REG_PC, 8);

	static const char *const cond[] = { "beq", "bne", "blt", "bge", "bltu", "bgeu",
	                                    "beqz", "bnez", "bceqz", "bcnez" };
	static const char *const pcrel[] = { "pcaddi", "pcaddu12i", "pcaddu18i", "pcalau12i" };
	g_kind = calloc(la_opcode_count, 1);
	g_pcrel = calloc(la_opcode_count, 1);
	if (!g_kind || !g_pcrel)
		return false;
	for (unsigned i = 0; i < la_opcode_count; i++) {
		const char *n = la_opcodes[i].name;
		for (size_t k = 0; k < sizeof(cond) / sizeof(cond[0]); k++)
			if (!strcmp(n, cond[k]))
				g_kind[i] = K_COND;
		for (size_t k = 0; k < sizeof(pcrel) / sizeof(pcrel[0]); k++)
			if (!strcmp(n, pcrel[k]))
				g_pcrel[i] = 1;
		if (!strcmp(n, "b"))
			g_kind[i] = K_B;
		else if (!strcmp(n, "bl"))
			g_kind[i] = K_BL;
		else if (!strcmp(n, "jirl"))
			g_kind[i] = K_JIRL;
		else if (!strcmp(n, "break"))
			g_kind[i] = K_BREAK;
		else if (!strcmp(n, "ertn"))
			g_kind[i] = K_ERTN;
	}
	return true;
}

static void arch_init(void *ctxt, BNArchitecture *obj) { (void)ctxt; g_arch = obj; }
static BNEndianness get_endianness(void *ctxt) { (void)ctxt; return LittleEndian; }
static size_t get_address_size(void *ctxt) { (void)ctxt; return 8; }
static size_t get_default_integer_size(void *ctxt) { (void)ctxt; return 4; }
static size_t get_instruction_alignment(void *ctxt) { (void)ctxt; return 4; }
static size_t get_max_instruction_length(void *ctxt) { (void)ctxt; return 4; }
static size_t get_opcode_display_length(void *ctxt) { (void)ctxt; return 4; }
static BNArchitecture *get_associated_arch(void *ctxt, uint64_t *addr) { (void)ctxt; (void)addr; return g_arch; }

static void add_branch(BNInstructionInfo *r, BNBranchType type, uint64_t target)
{
	if (r->branchCount >= BN_MAX_INSTRUCTION_BRANCHES)
		return;
	r->branchType[r->branchCount] = type;
	r->branchTarget[r->branchCount] = target;
	r->branchArch[r->branchCount] = NULL;
	r->branchCount++;
}

static bool get_instruction_info(void *ctxt, const uint8_t *data, uint64_t addr, size_t maxLen,
                                 BNInstructionInfo *result)
{
	(void)ctxt;
	la_insn insn;
	if (!la_decode(data, maxLen, addr, &insn))
		return false;
	result->length = 4;
	result->branchCount = 0;
	result->archTransitionByTargetAddr = false;
	result->delaySlots = 0;

	const la_operand *ops = insn.ops;
	switch (g_kind[insn.index]) {
	case K_COND:
		add_branch(result, TrueBranch, (uint64_t)ops[insn.nops - 1].value);
		add_branch(result, FalseBranch, addr + 4);
		break;
	case K_B:
		add_branch(result, UnconditionalBranch, (uint64_t)ops[0].value);
		break;
	case K_BL:
		add_branch(result, CallDestination, (uint64_t)ops[0].value);
		break;
	case K_JIRL: {
		int64_t rd = ops[0].value, rj = ops[1].value, off = ops[2].value;
		if (rd == 1)
			;
		else if (rd == 0 && rj == 1 && off == 0)
			add_branch(result, FunctionReturn, 0);
		else
			add_branch(result, IndirectBranch, 0);
		break;
	}
	case K_BREAK:
		if (ops[0].value == 0 || ops[0].value == 6 || ops[0].value == 7)
			add_branch(result, ExceptionBranch, 0);
		break;
	case K_ERTN:
		add_branch(result, FunctionReturn, 0);
		break;
	}
	return true;
}

static void make_token(BNInstructionTextToken *t, BNInstructionTextTokenType type, const char *text, uint64_t value)
{
	memset(t, 0, sizeof(*t));
	t->type = type;
	t->text = BNAllocString(text);
	t->value = value;
	t->width = strlen(text);
	t->size = 0;
	t->operand = 0xffffffff;
	t->context = NoTokenContext;
	t->confidence = BN_FULL_CONFIDENCE;
	t->address = 0;
	t->typeNames = NULL;
	t->namesCount = 0;
	t->exprIndex = BN_INVALID_EXPR;
}

static void hex(char *buf, size_t cap, uint64_t v) { snprintf(buf, cap, "0x%" PRIx64, v); }

static void imm_text(char *buf, size_t cap, unsigned type, int64_t v)
{
	if (type == LA_T_UIMM)
		hex(buf, cap, (uint64_t)v);
	else if (v > -4096 && v < 4096)
		snprintf(buf, cap, "%" PRId64, v);
	else if (v < 0)
		snprintf(buf, cap, "-0x%" PRIx64, (uint64_t)0 - (uint64_t)v);
	else
		hex(buf, cap, (uint64_t)v);
}

static bool get_instruction_text(void *ctxt, const uint8_t *data, uint64_t addr, size_t *len,
                                 BNInstructionTextToken **result, size_t *count)
{
	(void)ctxt;
	la_insn insn;
	if (!la_decode(data, *len, addr, &insn))
		return false;

	la_operand ops[LA_MAX_OPS];
	unsigned nops;
	const char *name;
	if (SHOW_ALIASES) {
		name = la_alias(&insn, ops, &nops);
	} else {
		name = la_name(&insn);
		nops = insn.nops;
		memcpy(ops, insn.ops, sizeof(ops));
	}

	BNInstructionTextToken *t = calloc(16, sizeof(*t));
	if (!t)
		return false;
	size_t n = 0;
	char buf[64];

	make_token(&t[n++], InstructionToken, name, 0);
	if (nops) {
		int pad = MNEMONIC_WIDTH - (int)strlen(name);
		if (pad < 1)
			pad = 1;
		memset(buf, ' ', (size_t)pad);
		buf[pad] = '\0';
		make_token(&t[n++], TextToken, buf, 0);
	}
	for (unsigned i = 0; i < nops; i++) {
		const la_operand *o = &ops[i];
		if (i)
			make_token(&t[n++], OperandSeparatorToken, ", ", 0);
		const char *reg = la_reg_name(o->type, (uint64_t)o->value);
		if (reg) {
			make_token(&t[n++], RegisterToken, reg, 0);
		} else if (o->type == LA_T_ADDR) {
			hex(buf, sizeof(buf), (uint64_t)o->value);
			make_token(&t[n++], PossibleAddressToken, buf, (uint64_t)o->value);
		} else {
			imm_text(buf, sizeof(buf), o->type, o->value);
			make_token(&t[n++], IntegerToken, buf, (uint64_t)o->value);
		}
	}
	if (g_pcrel[insn.index]) {
		uint64_t value = la_pcrel_value(&insn);
		make_token(&t[n++], TextToken, "  # ", 0);
		hex(buf, sizeof(buf), value);
		make_token(&t[n++], PossibleAddressToken, buf, value);
	}
	*len = 4;
	*result = t;
	*count = n;
	return true;
}

static void free_instruction_text(BNInstructionTextToken *tokens, size_t count)
{
	for (size_t i = 0; i < count; i++)
		BNFreeString(tokens[i].text);
	free(tokens);
}

#if BN_CURRENT_CORE_ABI_VERSION >= 164
static bool get_instruction_text_with_context(void *ctxt, const uint8_t *data, uint64_t addr, size_t *len,
                                              void *context, BNInstructionTextToken **result, size_t *count)
{
	(void)context;
	return get_instruction_text(ctxt, data, addr, len, result, count);
}
#endif

static bool get_instruction_low_level_il(void *ctxt, const uint8_t *data, uint64_t addr, size_t *len,
                                         BNLowLevelILFunction *il)
{
	(void)ctxt;
	la_insn insn;
	if (!la_decode(data, *len, addr, &insn))
		return false;
	la_lift(g_arch, &insn, il);
	*len = 4;
	return true;
}

static void analyze_basic_blocks(void *ctxt, BNFunction *function, BNBasicBlockAnalysisContext *context)
{
	(void)ctxt;
	BNArchitectureDefaultAnalyzeBasicBlocks(function, context);
}

#if BN_CURRENT_CORE_ABI_VERSION >= 164
static bool lift_function(void *ctxt, BNLowLevelILFunction *function, BNFunctionLifterContext *context)
{
	(void)ctxt;
	return BNArchitectureDefaultLiftFunction(function, context);
}

static void free_function_arch_context(void *ctxt, void *context) { (void)ctxt; (void)context; }
#endif

static uint32_t *reg_list(const uint32_t *regs, size_t n, size_t *count)
{
	uint32_t *out = malloc((n ? n : 1) * sizeof(uint32_t));
	if (!out) {
		*count = 0;
		return NULL;
	}
	if (n)
		memcpy(out, regs, n * sizeof(uint32_t));
	*count = n;
	return out;
}

static char *get_register_name(void *ctxt, uint32_t reg)
{
	(void)ctxt;
	return BNAllocString(reg < LA_REG_COUNT ? g_reg_name[reg] : "");
}

static uint32_t *get_full_width_registers(void *ctxt, size_t *count)
{
	(void)ctxt;
	uint32_t regs[LA_REG_COUNT];
	size_t n = 0;
	for (uint32_t i = 0; i < LA_REG_COUNT; i++)
		if (g_reg_info[i].fullWidthRegister == i)
			regs[n++] = i;
	return reg_list(regs, n, count);
}

static uint32_t *get_all_registers(void *ctxt, size_t *count)
{
	(void)ctxt;
	uint32_t regs[LA_REG_COUNT];
	for (uint32_t i = 0; i < LA_REG_COUNT; i++)
		regs[i] = i;
	return reg_list(regs, LA_REG_COUNT, count);
}

static void get_register_info(void *ctxt, uint32_t reg, BNRegisterInfo *result)
{
	(void)ctxt;
	if (reg < LA_REG_COUNT) {
		*result = g_reg_info[reg];
	} else {
		result->fullWidthRegister = 0;
		result->offset = 0;
		result->size = 0;
		result->extend = NoExtend;
	}
}

static uint32_t get_stack_pointer_register(void *ctxt) { (void)ctxt; return LA_REG_SP; }
static uint32_t get_link_register(void *ctxt) { (void)ctxt; return LA_REG_RA; }

static uint32_t *get_global_registers(void *ctxt, size_t *count)
{
	(void)ctxt;
	static const uint32_t regs[] = { LA_REG_TP };
	return reg_list(regs, 1, count);
}

static uint32_t *empty_list(void *ctxt, size_t *count) { (void)ctxt; return reg_list(NULL, 0, count); }
static void free_register_list(void *ctxt, uint32_t *regs, size_t count) { (void)ctxt; (void)count; free(regs); }

static char *empty_name(void *ctxt, uint32_t id) { (void)ctxt; (void)id; return BNAllocString(""); }
static BNFlagRole get_flag_role(void *ctxt, uint32_t flag, uint32_t sem_class)
{
	(void)ctxt; (void)flag; (void)sem_class;
	return SpecialFlagRole;
}
static uint32_t *get_flags_required_for_flag_condition(void *ctxt, BNLowLevelILFlagCondition cond,
                                                        uint32_t sem_class, size_t *count)
{
	(void)cond; (void)sem_class;
	return empty_list(ctxt, count);
}
static uint32_t *get_flags_for_id(void *ctxt, uint32_t id, size_t *count) { (void)id; return empty_list(ctxt, count); }
static BNFlagConditionForSemanticClass *get_flag_conditions_for_group(void *ctxt, uint32_t group, size_t *count)
{
	(void)ctxt; (void)group;
	*count = 0;
	return calloc(1, sizeof(BNFlagConditionForSemanticClass));
}
static void free_flag_conditions(void *ctxt, BNFlagConditionForSemanticClass *c, size_t count)
{
	(void)ctxt; (void)count;
	free(c);
}
static uint32_t get_semantic_class_for_flag_write_type(void *ctxt, uint32_t write_type)
{
	(void)ctxt; (void)write_type;
	return 0;
}
static size_t get_flag_write_low_level_il(void *ctxt, BNLowLevelILOperation op, size_t size, uint32_t write_type,
                                          uint32_t flag, BNRegisterOrConstant *operands, size_t operand_count,
                                          BNLowLevelILFunction *il)
{
	(void)ctxt; (void)write_type; (void)flag;
	return BNGetDefaultArchitectureFlagWriteLowLevelIL(g_arch, op, size, SpecialFlagRole, operands, operand_count, il);
}
static size_t get_flag_condition_low_level_il(void *ctxt, BNLowLevelILFlagCondition cond, uint32_t sem_class,
                                              BNLowLevelILFunction *il)
{
	(void)ctxt;
	return BNGetDefaultArchitectureFlagConditionLowLevelIL(g_arch, cond, sem_class, il);
}
static size_t get_semantic_flag_group_low_level_il(void *ctxt, uint32_t group, BNLowLevelILFunction *il)
{
	(void)ctxt; (void)group;
	return BNLowLevelILAddExpr(il, LLIL_UNIMPL, 0, 0, 0, 0, 0, 0);
}

static void get_register_stack_info(void *ctxt, uint32_t reg_stack, BNRegisterStackInfo *result)
{
	(void)ctxt; (void)reg_stack;
	memset(result, 0, sizeof(*result));
}

static BNIntrinsicClass get_intrinsic_class(void *ctxt, uint32_t intrinsic)
{
	(void)ctxt; (void)intrinsic;
	return GeneralIntrinsicClass;
}

static char *get_intrinsic_name(void *ctxt, uint32_t intrinsic)
{
	(void)ctxt;
	const char *name = la_intrinsic_name(intrinsic);
	return BNAllocString(name ? name : "");
}

static uint32_t *get_all_intrinsics(void *ctxt, size_t *count)
{
	(void)ctxt;
	unsigned n = la_intrinsic_count();
	uint32_t *out = malloc((n ? n : 1) * sizeof(uint32_t));
	if (!out) {
		*count = 0;
		return NULL;
	}
	for (unsigned i = 0; i < n; i++)
		out[i] = i;
	*count = n;
	return out;
}

static BNNameAndType *get_intrinsic_inputs(void *ctxt, uint32_t intrinsic, size_t *count)
{
	(void)ctxt;
	const uint8_t *sizes = NULL;
	unsigned n = la_intrinsic_inputs(intrinsic, &sizes);
	BNNameAndType *out = calloc(n ? n : 1, sizeof(*out));
	if (!out) {
		*count = 0;
		return NULL;
	}
	for (unsigned i = 0; i < n; i++) {
		out[i].name = BNAllocString("");
		out[i].type = BNNewTypeReference(g_int_type[sizes[i]]);
		out[i].typeConfidence = BN_FULL_CONFIDENCE;
	}
	*count = n;
	return out;
}

static void free_name_and_type_list(void *ctxt, BNNameAndType *nt, size_t count)
{
	(void)ctxt;
	for (size_t i = 0; i < count; i++) {
		BNFreeString(nt[i].name);
		BNFreeType(nt[i].type);
	}
	free(nt);
}

static BNTypeWithConfidence *get_intrinsic_outputs(void *ctxt, uint32_t intrinsic, size_t *count)
{
	(void)ctxt;
	const uint8_t *sizes = NULL;
	unsigned n = la_intrinsic_outputs(intrinsic, &sizes);
	BNTypeWithConfidence *out = calloc(n ? n : 1, sizeof(*out));
	if (!out) {
		*count = 0;
		return NULL;
	}
	for (unsigned i = 0; i < n; i++) {
		out[i].type = BNNewTypeReference(g_int_type[sizes[i]]);
		out[i].confidence = BN_FULL_CONFIDENCE;
	}
	*count = n;
	return out;
}

static void free_type_list(void *ctxt, BNTypeWithConfidence *types, size_t count)
{
	(void)ctxt;
	for (size_t i = 0; i < count; i++)
		BNFreeType(types[i].type);
	free(types);
}

static bool can_assemble(void *ctxt) { (void)ctxt; return false; }
static bool assemble(void *ctxt, const char *code, uint64_t addr, BNDataBuffer *result, char **errors)
{
	(void)ctxt; (void)code; (void)addr; (void)result;
	*errors = BNAllocString("Architecture does not implement an assembler.\n");
	return false;
}
static bool patch_check(void *ctxt, const uint8_t *data, uint64_t addr, size_t len)
{
	(void)ctxt; (void)data; (void)addr; (void)len;
	return false;
}
static bool patch_do(void *ctxt, uint8_t *data, uint64_t addr, size_t len)
{
	(void)ctxt; (void)data; (void)addr; (void)len;
	return false;
}
static bool skip_and_return_value(void *ctxt, uint8_t *data, uint64_t addr, size_t len, uint64_t value)
{
	(void)ctxt; (void)data; (void)addr; (void)len; (void)value;
	return false;
}

#if BN_CURRENT_CORE_ABI_VERSION >= 187
static size_t get_linear_sweep_initial_alignment(void *ctxt) { (void)ctxt; return 4; }
static uint32_t get_linear_sweep_analysis_capabilities(void *ctxt)
{
	(void)ctxt;
	return BNLinearSweepCallTargetAnalysis | BNLinearSweepGenericControlFlowAnalysis;
}
#endif

static BNCustomArchitecture g_cb = {
	.context = NULL,
	.init = arch_init,
	.getEndianness = get_endianness,
	.getAddressSize = get_address_size,
	.getDefaultIntegerSize = get_default_integer_size,
	.getInstructionAlignment = get_instruction_alignment,
	.getMaxInstructionLength = get_max_instruction_length,
	.getOpcodeDisplayLength = get_opcode_display_length,
	.getAssociatedArchitectureByAddress = get_associated_arch,
	.getInstructionInfo = get_instruction_info,
	.getInstructionText = get_instruction_text,
#if BN_CURRENT_CORE_ABI_VERSION >= 164
	.getInstructionTextWithContext = get_instruction_text_with_context,
#endif
	.freeInstructionText = free_instruction_text,
	.getInstructionLowLevelIL = get_instruction_low_level_il,
	.analyzeBasicBlocks = analyze_basic_blocks,
#if BN_CURRENT_CORE_ABI_VERSION >= 164
	.liftFunction = lift_function,
	.freeFunctionArchContext = free_function_arch_context,
#endif
	.getRegisterName = get_register_name,
	.getFlagName = empty_name,
	.getFlagWriteTypeName = empty_name,
	.getSemanticFlagClassName = empty_name,
	.getSemanticFlagGroupName = empty_name,
	.getFullWidthRegisters = get_full_width_registers,
	.getAllRegisters = get_all_registers,
	.getAllFlags = empty_list,
	.getAllFlagWriteTypes = empty_list,
	.getAllSemanticFlagClasses = empty_list,
	.getAllSemanticFlagGroups = empty_list,
	.getFlagRole = get_flag_role,
	.getFlagsRequiredForFlagCondition = get_flags_required_for_flag_condition,
	.getFlagsRequiredForSemanticFlagGroup = get_flags_for_id,
	.getFlagConditionsForSemanticFlagGroup = get_flag_conditions_for_group,
	.freeFlagConditionsForSemanticFlagGroup = free_flag_conditions,
	.getFlagsWrittenByFlagWriteType = get_flags_for_id,
	.getSemanticClassForFlagWriteType = get_semantic_class_for_flag_write_type,
	.getFlagWriteLowLevelIL = get_flag_write_low_level_il,
	.getFlagConditionLowLevelIL = get_flag_condition_low_level_il,
	.getSemanticFlagGroupLowLevelIL = get_semantic_flag_group_low_level_il,
	.freeRegisterList = free_register_list,
	.getRegisterInfo = get_register_info,
	.getStackPointerRegister = get_stack_pointer_register,
	.getLinkRegister = get_link_register,
	.getGlobalRegisters = get_global_registers,
	.getSystemRegisters = empty_list,
	.getRegisterStackName = empty_name,
	.getAllRegisterStacks = empty_list,
	.getRegisterStackInfo = get_register_stack_info,
	.getIntrinsicClass = get_intrinsic_class,
	.getIntrinsicName = get_intrinsic_name,
	.getAllIntrinsics = get_all_intrinsics,
	.getIntrinsicInputs = get_intrinsic_inputs,
	.freeNameAndTypeList = free_name_and_type_list,
	.getIntrinsicOutputs = get_intrinsic_outputs,
	.freeTypeList = free_type_list,
	.canAssemble = can_assemble,
	.assemble = assemble,
	.isNeverBranchPatchAvailable = patch_check,
	.isAlwaysBranchPatchAvailable = patch_check,
	.isInvertBranchPatchAvailable = patch_check,
	.isSkipAndReturnZeroPatchAvailable = patch_check,
	.isSkipAndReturnValuePatchAvailable = patch_check,
	.convertToNop = patch_do,
	.alwaysBranch = patch_do,
	.invertBranch = patch_do,
	.skipAndReturnValue = skip_and_return_value,
#if BN_CURRENT_CORE_ABI_VERSION >= 187
	.getLinearSweepInitialAlignment = get_linear_sweep_initial_alignment,
	.getLinearSweepAnalysisCapabilities = get_linear_sweep_analysis_capabilities,
#endif
};

BNCustomArchitecture *la_arch_callbacks(void) { return &g_cb; }

BNArchitecture *la_register_architecture(void)
{
	if (!la_arch_init_tables())
		return NULL;

	BNBoolWithConfidence is_signed = { false, BN_FULL_CONFIDENCE };
	for (unsigned i = 0; i < la_intrinsic_count(); i++) {
		const uint8_t *sizes;
		unsigned n = la_intrinsic_inputs(i, &sizes);
		for (unsigned k = 0; k < n; k++)
			if (!g_int_type[sizes[k]])
				g_int_type[sizes[k]] = BNCreateIntegerType(sizes[k], &is_signed, "");
		n = la_intrinsic_outputs(i, &sizes);
		for (unsigned k = 0; k < n; k++)
			if (!g_int_type[sizes[k]])
				g_int_type[sizes[k]] = BNCreateIntegerType(sizes[k], &is_signed, "");
	}

	BNArchitecture *arch = BNRegisterArchitecture(LA_ARCH_NAME, &g_cb);
	if (arch)
		g_arch = arch;
	return g_arch;
}
