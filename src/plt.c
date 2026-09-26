#include <stdlib.h>
#include <string.h>

#include "la64_bn.h"

#define R_LARCH_JUMP_SLOT 5

typedef struct {
	uint64_t slot;
	char *name;
} got_name;

static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }

static bool section_range(BNBinaryView *view, const char *name, uint64_t *start, uint64_t *end)
{
	BNSection *s = BNGetSectionByName(view, name);
	if (!s)
		return false;
	*start = BNSectionGetStart(s);
	*end = *start + BNSectionGetLength(s);
	BNFreeSection(s);
	return true;
}

static void read_cstr(BNBinaryView *view, uint64_t addr, char *out, size_t limit)
{
	size_t n = BNReadViewData(view, out, addr, limit);
	out[n] = '\0';
}

static bool stub_got_slot(BNBinaryView *view, uint64_t addr, uint64_t *slot)
{
	uint8_t wa[4], wb[4];
	la_insn a, b;
	size_t na = BNReadViewData(view, wa, addr, 4);
	size_t nb = BNReadViewData(view, wb, addr + 4, 4);
	if (!la_decode(wa, na, addr, &a) || !la_decode(wb, nb, addr + 4, &b))
		return false;
	if (strcmp(la_name(&a), "pcaddu12i") || strcmp(la_name(&b), "ld.d"))
		return false;
	int64_t reg = a.ops[0].value, hi = a.ops[1].value;
	if (b.ops[1].value != reg)
		return false;
	*slot = addr + ((uint64_t)hi << 12) + (uint64_t)b.ops[2].value;
	return true;
}

static const char *find_name(const got_name *names, size_t n, uint64_t slot)
{
	for (size_t i = 0; i < n; i++)
		if (names[i].slot == slot)
			return names[i].name;
	return NULL;
}

size_t la_name_plt_stubs(BNBinaryView *view)
{
	uint64_t plt_s, plt_e, rela_s, rela_e, dynsym_s, dynsym_e, dynstr_s, dynstr_e;
	if (!section_range(view, ".plt", &plt_s, &plt_e) || !section_range(view, ".rela.plt", &rela_s, &rela_e) ||
	    !section_range(view, ".dynsym", &dynsym_s, &dynsym_e) || !section_range(view, ".dynstr", &dynstr_s, &dynstr_e))
		return 0;

	size_t rela_len = (size_t)(rela_e - rela_s);
	uint8_t *data = malloc(rela_len ? rela_len : 1);
	if (!data)
		return 0;
	size_t got = BNReadViewData(view, data, rela_s, rela_len);
	got_name *names = NULL;
	size_t n_names = 0;
	for (size_t off = 0; off + 24 <= got; off += 24) {
		uint64_t r_offset = le64(data + off);
		uint64_t r_info = le64(data + off + 8);
		if ((r_info & 0xffffffffu) != R_LARCH_JUMP_SLOT)
			continue;
		uint8_t sym[24];
		if (BNReadViewData(view, sym, dynsym_s + 24 * (r_info >> 32), 24) < 4)
			continue;
		char name[257];
		read_cstr(view, dynstr_s + le32(sym), name, 256);
		if (!name[0])
			continue;
		size_t len = strlen(name);
		char *copy = malloc(len + 1);
		if (!copy)
			continue;
		memcpy(copy, name, len + 1);
		size_t i = 0;
		while (i < n_names && names[i].slot != r_offset)
			i++;
		if (i < n_names) {
			free(names[i].name);
			names[i].name = copy;
			continue;
		}
		got_name *grown = realloc(names, (n_names + 1) * sizeof(*names));
		if (!grown) {
			free(copy);
			continue;
		}
		names = grown;
		names[n_names].slot = r_offset;
		names[n_names].name = copy;
		n_names++;
	}
	free(data);

	size_t count = 0;
	BNPlatform *platform = BNGetDefaultPlatform(view);
	for (uint64_t addr = plt_s; addr + 15 < plt_e; addr += 4) {
		uint64_t slot;
		if (!stub_got_slot(view, addr, &slot))
			continue;
		const char *name = find_name(names, n_names, slot);
		if (!name)
			continue;
		BNSymbol *sym = BNCreateSymbol(ImportAddressSymbol, name, name, name, slot, NoBinding, NULL, 0);
		BNDefineAutoSymbol(view, sym);
		BNFreeSymbol(sym);
		sym = BNCreateSymbol(ImportedFunctionSymbol, name, name, name, addr, NoBinding, NULL, 0);
		BNDefineAutoSymbol(view, sym);
		BNFreeSymbol(sym);
		if (platform) {
			BNFunction *func = BNAddFunctionForAnalysis(view, platform, addr, false, NULL);
			if (func)
				BNFreeFunction(func);
		}
		count++;
	}
	if (platform)
		BNFreePlatform(platform);
	for (size_t i = 0; i < n_names; i++)
		free(names[i].name);
	free(names);
	return count;
}
