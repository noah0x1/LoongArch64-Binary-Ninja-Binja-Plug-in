#include <stdlib.h>
#include <string.h>

#include "la64_bn.h"

typedef struct cc_def {
	const char *name;
	const uint32_t *int_args;      size_t n_int_args;
	const uint32_t *float_args;    size_t n_float_args;
	const uint32_t *caller_saved;  size_t n_caller_saved;
	const uint32_t *callee_saved;  size_t n_callee_saved;
	uint32_t int_ret, high_int_ret, float_ret;
	bool eligible_for_heuristics;
	BNCallingConvention *handle;
} cc_def;

#define N(a) (sizeof(a) / sizeof((a)[0]))
#define FA(i) LA_REG_FPR(i)
#define FT(i) LA_REG_FPR(8 + (i))
#define FS(i) LA_REG_FPR(24 + (i))

static const uint32_t LP64D_INT_ARGS[] = {
	LA_REG_A(0), LA_REG_A(1), LA_REG_A(2), LA_REG_A(3), LA_REG_A(4), LA_REG_A(5), LA_REG_A(6), LA_REG_A(7),
};
static const uint32_t LP64D_FLOAT_ARGS[] = { FA(0), FA(1), FA(2), FA(3), FA(4), FA(5), FA(6), FA(7) };
static const uint32_t LP64D_CALLER_SAVED[] = {
	LA_REG_RA,
	LA_REG_A(0), LA_REG_A(1), LA_REG_A(2), LA_REG_A(3), LA_REG_A(4), LA_REG_A(5), LA_REG_A(6), LA_REG_A(7),
	LA_REG_T(0), LA_REG_T(1), LA_REG_T(2), LA_REG_T(3), LA_REG_T(4), LA_REG_T(5), LA_REG_T(6), LA_REG_T(7), LA_REG_T(8),
	FA(0), FA(1), FA(2), FA(3), FA(4), FA(5), FA(6), FA(7),
	FT(0), FT(1), FT(2), FT(3), FT(4), FT(5), FT(6), FT(7),
	FT(8), FT(9), FT(10), FT(11), FT(12), FT(13), FT(14), FT(15),
};
static const uint32_t LP64D_CALLEE_SAVED[] = {
	LA_REG_S(0), LA_REG_S(1), LA_REG_S(2), LA_REG_S(3), LA_REG_S(4), LA_REG_S(5), LA_REG_S(6), LA_REG_S(7), LA_REG_S(8),
	LA_REG_FP,
	FS(0), FS(1), FS(2), FS(3), FS(4), FS(5), FS(6), FS(7),
};

static const uint32_t SYSCALL_INT_ARGS[] = {
	LA_REG_A(7), LA_REG_A(0), LA_REG_A(1), LA_REG_A(2), LA_REG_A(3), LA_REG_A(4), LA_REG_A(5), LA_REG_A(6),
};
static const uint32_t SYSCALL_CALLER_SAVED[] = {
	LA_REG_A(0),
	LA_REG_T(0), LA_REG_T(1), LA_REG_T(2), LA_REG_T(3), LA_REG_T(4), LA_REG_T(5), LA_REG_T(6), LA_REG_T(7), LA_REG_T(8),
};

static cc_def g_lp64d = {
	"lp64d",
	LP64D_INT_ARGS, N(LP64D_INT_ARGS), LP64D_FLOAT_ARGS, N(LP64D_FLOAT_ARGS),
	LP64D_CALLER_SAVED, N(LP64D_CALLER_SAVED), LP64D_CALLEE_SAVED, N(LP64D_CALLEE_SAVED),
	LA_REG_A(0), LA_REG_A(1), FA(0), true, NULL,
};

static cc_def g_syscall = {
	"linux-syscall",
	SYSCALL_INT_ARGS, N(SYSCALL_INT_ARGS), NULL, 0,
	SYSCALL_CALLER_SAVED, N(SYSCALL_CALLER_SAVED), NULL, 0,
	LA_REG_A(0), BN_INVALID_REGISTER, BN_INVALID_REGISTER, false, NULL,
};

static uint32_t *copy_regs(const uint32_t *regs, size_t n, size_t *count)
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

#define CC ((const cc_def *)ctxt)

static void free_object(void *ctxt) { (void)ctxt; }
static uint32_t *caller_saved(void *ctxt, size_t *count) { return copy_regs(CC->caller_saved, CC->n_caller_saved, count); }
static uint32_t *callee_saved(void *ctxt, size_t *count) { return copy_regs(CC->callee_saved, CC->n_callee_saved, count); }
static uint32_t *int_args(void *ctxt, size_t *count) { return copy_regs(CC->int_args, CC->n_int_args, count); }
static uint32_t *float_args(void *ctxt, size_t *count) { return copy_regs(CC->float_args, CC->n_float_args, count); }
static uint32_t *no_regs(void *ctxt, size_t *count) { (void)ctxt; return copy_regs(NULL, 0, count); }
static void free_regs(void *ctxt, uint32_t *regs, size_t len) { (void)ctxt; (void)len; free(regs); }

static bool no(void *ctxt) { (void)ctxt; return false; }
static bool yes(void *ctxt) { (void)ctxt; return true; }
static bool heuristics(void *ctxt) { return CC->eligible_for_heuristics; }

static uint32_t int_ret(void *ctxt) { return CC->int_ret; }
static uint32_t high_int_ret(void *ctxt) { return CC->high_int_ret; }
static uint32_t float_ret(void *ctxt) { return CC->float_ret; }

static void incoming_undetermined(void *ctxt, uint32_t reg, BNFunction *func, BNRegisterValue *result)
{
	(void)ctxt; (void)reg; (void)func;
	result->state = UndeterminedValue;
	result->value = 0;
	result->offset = 0;
	result->size = 0;
}

static void incoming_var_for_param_var(void *ctxt, const BNVariable *var, BNFunction *func, BNVariable *result)
{
	(void)func;
	*result = BNGetDefaultIncomingVariableForParameterVariable(CC->handle, var);
}

static void param_var_for_incoming_var(void *ctxt, const BNVariable *var, BNFunction *func, BNVariable *result)
{
	(void)func;
	*result = BNGetDefaultParameterVariableForIncomingVariable(CC->handle, var);
}

#if BN_CURRENT_CORE_ABI_VERSION >= 187
static bool return_type_reg_compatible(void *ctxt, BNBinaryView *view, BNType *type)
{
	(void)view;
	return type ? BNDefaultIsReturnTypeRegisterCompatible(CC->handle, type) : false;
}

static void indirect_return_value_location(void *ctxt, BNVariable *out)
{
	*out = BNGetDefaultIndirectReturnValueLocation(CC->handle);
}

static bool returned_indirect_return_value_pointer(void *ctxt, BNVariable *out)
{
	(void)ctxt; (void)out;
	return false;
}

static bool arg_type_reg_compatible(void *ctxt, BNBinaryView *view, BNType *type)
{
	(void)view;
	return type ? BNDefaultIsArgumentTypeRegisterCompatible(CC->handle, type) : false;
}

static bool non_reg_arg_indirect(void *ctxt, BNBinaryView *view, BNType *type)
{
	(void)ctxt; (void)view; (void)type;
	return false;
}

static void call_layout(void *ctxt, BNBinaryView *view, BNReturnValue *ret, BNFunctionParameter *params,
                        size_t n, bool has_permitted, uint32_t *permitted, size_t n_permitted, BNCallLayout *result)
{
	if (has_permitted)
		*result = BNGetDefaultCallLayout(CC->handle, view, ret, params, n, permitted, n_permitted);
	else
		*result = BNGetDefaultCallLayoutDefaultPermittedArgs(CC->handle, view, ret, params, n);
}

static void free_call_layout(void *ctxt, BNCallLayout *layout) { (void)ctxt; BNFreeCallLayout(layout); }

static void return_value_location(void *ctxt, BNBinaryView *view, BNReturnValue *ret, BNValueLocation *out)
{
	*out = BNGetDefaultReturnValueLocation(CC->handle, view, ret);
}

static void free_value_location(void *ctxt, BNValueLocation *loc) { (void)ctxt; BNFreeValueLocation(loc); }

static BNValueLocation *parameter_locations(void *ctxt, BNBinaryView *view, BNValueLocation *ret,
                                            BNFunctionParameter *params, size_t n, bool has_permitted,
                                            uint32_t *permitted, size_t n_permitted, size_t *out_count)
{
	if (has_permitted)
		return BNGetDefaultParameterLocations(CC->handle, view, ret, params, n, permitted, n_permitted, out_count);
	return BNGetDefaultParameterLocationsDefaultPermittedArgs(CC->handle, view, ret, params, n, out_count);
}

static void free_parameter_locations(void *ctxt, BNValueLocation *locs, size_t count)
{
	(void)ctxt;
	BNFreeValueLocationList(locs, count);
}

static BNVariable *parameter_ordering(void *ctxt, BNBinaryView *view, BNVariable *vars, BNType **types,
                                      size_t n, size_t *out_count)
{
	(void)view;
	return BNGetDefaultParameterOrderingForVariables(CC->handle, vars, (const BNType **)types, n, out_count);
}

static void free_variable_list(void *ctxt, BNVariable *vars, size_t count)
{
	(void)ctxt; (void)count;
	BNFreeVariableList(vars);
}

static int64_t stack_adjustment(void *ctxt, BNBinaryView *view, BNValueLocation *ret, BNValueLocation *locs,
                                BNType **types, size_t n)
{
	(void)view;
	return BNGetDefaultStackAdjustmentForLocations(CC->handle, ret, locs, (const BNType **)types, n);
}

static size_t register_stack_adjustments(void *ctxt, BNBinaryView *view, BNValueLocation *ret,
                                         BNValueLocation *params, size_t n, uint32_t **out_regs, int32_t **out_adjust)
{
	(void)view;
	return BNGetCallingConventionDefaultRegisterStackAdjustments(CC->handle, ret, params, n, out_regs, out_adjust);
}

static void free_register_stack_adjustments(void *ctxt, uint32_t *regs, int32_t *adjust, size_t count)
{
	(void)ctxt; (void)count;
	BNFreeCallingConventionRegisterStackAdjustments(regs, adjust);
}
#else
static uint32_t global_pointer_reg(void *ctxt) { (void)ctxt; return BN_INVALID_REGISTER; }
#endif

static BNCallingConvention *create(BNArchitecture *arch, cc_def *def)
{
	BNCustomCallingConvention cb;
	memset(&cb, 0, sizeof(cb));
	cb.context = def;
	cb.freeObject = free_object;
	cb.getCallerSavedRegisters = caller_saved;
	cb.getCalleeSavedRegisters = callee_saved;
	cb.getIntegerArgumentRegisters = int_args;
	cb.getFloatArgumentRegisters = float_args;
#if BN_CURRENT_CORE_ABI_VERSION >= 164
	cb.getRequiredArgumentRegisters = no_regs;
	cb.getRequiredClobberedRegisters = no_regs;
#endif
	cb.freeRegisterList = free_regs;
	cb.areArgumentRegistersSharedIndex = no;
	cb.isStackReservedForArgumentRegisters = no;
	cb.isStackAdjustedOnReturn = no;
	cb.isEligibleForHeuristics = heuristics;
	cb.getIntegerReturnValueRegister = int_ret;
	cb.getHighIntegerReturnValueRegister = high_int_ret;
	cb.getFloatReturnValueRegister = float_ret;
#if BN_CURRENT_CORE_ABI_VERSION >= 187
	cb.getGlobalPointerRegisters = no_regs;
#else
	cb.getGlobalPointerRegister = global_pointer_reg;
#endif
	cb.getImplicitlyDefinedRegisters = no_regs;
	cb.getIncomingRegisterValue = incoming_undetermined;
	cb.getIncomingFlagValue = incoming_undetermined;
	cb.getIncomingVariableForParameterVariable = incoming_var_for_param_var;
	cb.getParameterVariableForIncomingVariable = param_var_for_incoming_var;
	cb.areArgumentRegistersUsedForVarArgs = yes;
#if BN_CURRENT_CORE_ABI_VERSION >= 187
	cb.isReturnTypeRegisterCompatible = return_type_reg_compatible;
	cb.getIndirectReturnValueLocation = indirect_return_value_location;
	cb.getReturnedIndirectReturnValuePointer = returned_indirect_return_value_pointer;
	cb.isArgumentTypeRegisterCompatible = arg_type_reg_compatible;
	cb.isNonRegisterArgumentIndirect = non_reg_arg_indirect;
	cb.areStackArgumentsNaturallyAligned = no;
	cb.areStackArgumentsPushedLeftToRight = no;
	cb.getCallLayout = call_layout;
	cb.freeCallLayout = free_call_layout;
	cb.getReturnValueLocation = return_value_location;
	cb.freeValueLocation = free_value_location;
	cb.getParameterLocations = parameter_locations;
	cb.freeParameterLocations = free_parameter_locations;
	cb.getParameterOrderingForVariables = parameter_ordering;
	cb.freeVariableList = free_variable_list;
	cb.getStackAdjustmentForLocations = stack_adjustment;
	cb.getRegisterStackAdjustments = register_stack_adjustments;
	cb.freeRegisterStackAdjustments = free_register_stack_adjustments;
#endif
	def->handle = BNCreateCallingConvention(arch, def->name, &cb);
	return def->handle;
}

BNCallingConvention *la_create_default_cc(BNArchitecture *arch) { return create(arch, &g_lp64d); }
BNCallingConvention *la_create_syscall_cc(BNArchitecture *arch) { return create(arch, &g_syscall); }
