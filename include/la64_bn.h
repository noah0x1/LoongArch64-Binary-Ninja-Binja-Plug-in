#ifndef LA64_BN_H
#define LA64_BN_H

#include "binaryninjacore.h"
#include "la64.h"

#define LA_ARCH_NAME "LoongArch64"

LA_HIDDEN bool la_lift_init(void);
LA_HIDDEN void la_lift(BNArchitecture *arch, const la_insn *insn, BNLowLevelILFunction *il);
LA_HIDDEN const char *la_lifter_name(unsigned opcode_index);

LA_HIDDEN unsigned la_intrinsic_count(void);
LA_HIDDEN const char *la_intrinsic_name(unsigned idx);
LA_HIDDEN unsigned la_intrinsic_inputs(unsigned idx, const uint8_t **sizes);
LA_HIDDEN unsigned la_intrinsic_outputs(unsigned idx, const uint8_t **sizes);

LA_HIDDEN BNArchitecture *la_register_architecture(void);
LA_HIDDEN bool la_arch_init_tables(void);
LA_HIDDEN BNCustomArchitecture *la_arch_callbacks(void);

LA_HIDDEN BNCallingConvention *la_create_default_cc(BNArchitecture *arch);
LA_HIDDEN BNCallingConvention *la_create_syscall_cc(BNArchitecture *arch);

LA_HIDDEN size_t la_name_plt_stubs(BNBinaryView *view);

#endif
