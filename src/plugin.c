#include <string.h>

#include "la64_bn.h"

#define EM_LOONGARCH 258

static bool is_la64(void *ctxt, BNBinaryView *view)
{
	(void)ctxt;
	BNArchitecture *arch = BNGetDefaultArchitecture(view);
	if (!arch)
		return false;
	char *name = BNGetArchitectureName(arch);
	bool ok = name && !strcmp(name, LA_ARCH_NAME);
	BNFreeString(name);
	return ok;
}

static void name_plt(void *ctxt, BNBinaryView *view)
{
	if (!is_la64(ctxt, view))
		return;
	char *type = BNGetViewType(view);
	bool elf = type && !strcmp(type, "ELF");
	BNFreeString(type);
	if (!elf)
		return;
	size_t n = la_name_plt_stubs(view);
	if (n)
		BNLogInfo("LoongArch64: named %llu PLT stubs", (unsigned long long)n);
}

BINARYNINJAPLUGIN uint32_t CorePluginABIVersion(void)
{
	return BN_CURRENT_CORE_ABI_VERSION;
}

BINARYNINJAPLUGIN void CorePluginDependencies(void)
{
	BNAddOptionalPluginDependency("view_elf");
}

static bool g_initialized;

BINARYNINJAPLUGIN bool CorePluginInit(void)
{
	if (g_initialized)
		return true;
	if (!la_init() || !la_lift_init()) {
		BNLogError("LoongArch64: could not build opcode tables");
		return false;
	}

	BNArchitecture *arch = la_register_architecture();
	if (!arch) {
		BNLogError("LoongArch64: architecture registration failed");
		return false;
	}

	BNCallingConvention *cc = la_create_default_cc(arch);
	BNCallingConvention *sys = la_create_syscall_cc(arch);
	if (!cc || !sys) {
		BNLogError("LoongArch64: calling convention creation failed");
		return false;
	}
	BNRegisterCallingConvention(arch, cc);
	BNRegisterCallingConvention(arch, sys);

	BNPlatform *standalone = BNGetArchitectureStandalonePlatform(arch);
	if (standalone) {
		BNRegisterPlatformDefaultCallingConvention(standalone, cc);
		BNFreePlatform(standalone);
	}

	BNPlatform *linux_platform = BNCreatePlatform(arch, "linux-loongarch64");
	if (linux_platform) {
		BNRegisterPlatformDefaultCallingConvention(linux_platform, cc);
		BNSetPlatformSystemCallConvention(linux_platform, sys);
		BNRegisterPlatform("linux", linux_platform);
	}

	BNBinaryViewType *elf = BNGetBinaryViewTypeByName("ELF");
	if (elf) {
		BNRegisterArchitectureForViewType(elf, EM_LOONGARCH, LittleEndian, arch);
		if (linux_platform) {
			BNRegisterPlatformForViewType(elf, 0, arch, linux_platform);
			BNRegisterPlatformForViewType(elf, 3, arch, linux_platform);
		}
	} else {
		BNLogError("LoongArch64: ELF registration failed: ELF view type not found");
	}

	BNRegisterPluginCommand("LoongArch64\\Name PLT stubs",
	                        "Name PLT stubs of a dynamically linked LoongArch64 ELF",
	                        name_plt, is_la64, NULL);
	BNRegisterBinaryViewEvent(BinaryViewFinalizationEvent, name_plt, NULL);

	BNLogInfo("LoongArch64 architecture loaded (%u opcodes)", la_opcode_count);
	g_initialized = true;
	return true;
}
