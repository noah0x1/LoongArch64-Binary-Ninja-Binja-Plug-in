#include <stdlib.h>
#include <string.h>

#include "la64.h"

la_spec la_specs[LA_MAX_SPECS];
la_opinfo *la_info;
uint32_t la_bucket_start[LA_NBUCKETS + 1];
uint16_t *la_bucket_list;

static const char *spec_strings[LA_MAX_SPECS];
static unsigned spec_count;

static const char *const GPR[32] = {
	"$zero", "$ra", "$tp", "$sp",
	"$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7",
	"$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8",
	"$r21", "$fp",
	"$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$s8",
};
static const char *const FPR[32] = {
	"$fa0", "$fa1", "$fa2", "$fa3", "$fa4", "$fa5", "$fa6", "$fa7",
	"$ft0", "$ft1", "$ft2", "$ft3", "$ft4", "$ft5", "$ft6", "$ft7",
	"$ft8", "$ft9", "$ft10", "$ft11", "$ft12", "$ft13", "$ft14", "$ft15",
	"$fs0", "$fs1", "$fs2", "$fs3", "$fs4", "$fs5", "$fs6", "$fs7",
};
static char VR[32][8], XR[32][8], FCC[8][8], FCSR[4][8], SCR[4][8];

const char *la_reg_name(unsigned type, uint64_t v)
{
	switch (type) {
	case LA_T_GPR:  return v < 32 ? GPR[v] : "?";
	case LA_T_FPR:  return v < 32 ? FPR[v] : "?";
	case LA_T_VR:   return v < 32 ? VR[v] : "?";
	case LA_T_XR:   return v < 32 ? XR[v] : "?";
	case LA_T_FCC:  return v < 8 ? FCC[v] : "?";
	case LA_T_FCSR: return v < 4 ? FCSR[v] : "?";
	case LA_T_SCR:  return v < 4 ? SCR[v] : "?";
	default:        return NULL;
	}
}

static bool parse_uint(const char **p, unsigned *out)
{
	const char *s = *p;
	unsigned v = 0;
	if (*s < '0' || *s > '9')
		return false;
	while (*s >= '0' && *s <= '9')
		v = v * 10 + (unsigned)(*s++ - '0');
	*p = s;
	*out = v;
	return true;
}

static bool parse_spec(const char *s, la_spec *out)
{
	memset(out, 0, sizeof(*out));

	if (strlen(s) == 2 && strchr("rfvx", s[0]) && strchr("djka", s[1])) {
		static const uint8_t type[] = { LA_T_GPR, LA_T_FPR, LA_T_VR, LA_T_XR };
		static const uint8_t pos[] = { 0, 5, 10, 15 };
		unsigned t = (unsigned)(strchr("rfvx", s[0]) - "rfvx");
		unsigned f = (unsigned)(strchr("djka", s[1]) - "djka");
		out->kind = LA_K_UFIELD;
		out->type = type[t];
		out->pos = pos[f];
		out->width = 5;
		out->slot = (uint8_t)(LA_S_RD + t * 4 + f);
		return true;
	}
	static const struct { const char *name; uint8_t type, pos, width, slot; } named[] = {
		{ "cd", LA_T_FCC, 0, 3, LA_S_CD },       { "cj", LA_T_FCC, 5, 3, LA_S_CJ },
		{ "ca", LA_T_FCC, 15, 3, LA_S_CA },
		{ "fcsrd", LA_T_FCSR, 0, 2, LA_S_FCSRD }, { "fcsrj", LA_T_FCSR, 5, 2, LA_S_FCSRJ },
		{ "scrd", LA_T_SCR, 0, 2, LA_S_SCRD },    { "scrj", LA_T_SCR, 5, 2, LA_S_SCRJ },
	};
	for (size_t i = 0; i < sizeof(named) / sizeof(named[0]); i++) {
		if (!strcmp(s, named[i].name)) {
			out->kind = LA_K_UFIELD;
			out->type = named[i].type;
			out->pos = named[i].pos;
			out->width = named[i].width;
			out->slot = named[i].slot;
			return true;
		}
	}

	if (!strcmp(s, "off16")) {
		*out = (la_spec){ .kind = LA_K_SFIELD, .type = LA_T_ADDR, .pos = 10, .width = 16, .shift = 2, .pcrel = 1 };
		return true;
	}
	if (!strcmp(s, "off21")) {
		*out = (la_spec){ .kind = LA_K_SPLIT21, .type = LA_T_ADDR, .shift = 2, .pcrel = 1 };
		return true;
	}
	if (!strcmp(s, "off26")) {
		*out = (la_spec){ .kind = LA_K_SPLIT26, .type = LA_T_ADDR, .shift = 2, .pcrel = 1 };
		return true;
	}
	if (!strcmp(s, "sx21<<2")) {
		*out = (la_spec){ .kind = LA_K_SPLIT21, .type = LA_T_IMM, .shift = 2 };
		return true;
	}

	bool is_signed;
	if (!strncmp(s, "si", 2))
		is_signed = true;
	else if (!strncmp(s, "ui", 2))
		is_signed = false;
	else
		return false;
	const char *p = s + 2;
	unsigned width, pos = 10, shift = 0, add = 0;
	if (!parse_uint(&p, &width))
		return false;
	if (*p == '@') {
		p++;
		if (!parse_uint(&p, &pos))
			return false;
	}
	if (p[0] == '<' && p[1] == '<') {
		p += 2;
		if (!parse_uint(&p, &shift))
			return false;
	}
	if (*p == '+') {
		p++;
		if (!parse_uint(&p, &add))
			return false;
	}
	if (*p != '\0' || width == 0 || width > 32 || pos + width > 32 || shift > 63 || add > 255)
		return false;
	out->kind = is_signed ? LA_K_SFIELD : LA_K_UFIELD;
	out->type = is_signed ? LA_T_IMM : LA_T_UIMM;
	out->pos = (uint8_t)pos;
	out->width = (uint8_t)width;
	out->shift = (uint8_t)shift;
	out->add = (uint8_t)add;
	return true;
}

static int spec_index(const char *s, size_t len)
{
	char buf[32];
	if (len == 0 || len >= sizeof(buf))
		return -1;
	memcpy(buf, s, len);
	buf[len] = '\0';
	for (unsigned i = 0; i < spec_count; i++)
		if (!strcmp(spec_strings[i], buf))
			return (int)i;
	if (spec_count >= LA_MAX_SPECS || !parse_spec(buf, &la_specs[spec_count]))
		return -1;
	char *copy = malloc(len + 1);
	if (!copy)
		return -1;
	memcpy(copy, buf, len + 1);
	spec_strings[spec_count] = copy;
	return (int)spec_count++;
}

bool la_init(void)
{
	for (int i = 0; i < 32; i++) {
		char num[4];
		int n = 0;
		if (i >= 10)
			num[n++] = (char)('0' + i / 10);
		num[n++] = (char)('0' + i % 10);
		num[n] = '\0';
		strcpy(VR[i], "$vr"); strcat(VR[i], num);
		strcpy(XR[i], "$xr"); strcat(XR[i], num);
		if (i < 8) { strcpy(FCC[i], "$fcc"); strcat(FCC[i], num); }
		if (i < 4) {
			strcpy(FCSR[i], "$fcsr"); strcat(FCSR[i], num);
			strcpy(SCR[i], "$scr"); strcat(SCR[i], num);
		}
	}

	unsigned n = la_opcode_count;
	la_info = calloc(n, sizeof(*la_info));
	if (!la_info)
		return false;

	for (unsigned i = 0; i < n; i++) {
		const char *s = la_opcodes[i].specs;
		while (*s) {
			const char *end = strchr(s, ',');
			size_t len = end ? (size_t)(end - s) : strlen(s);
			if (len) {
				int idx = spec_index(s, len);
				if (idx < 0 || la_info[i].nops >= LA_MAX_OPS)
					return false;
				la_info[i].spec[la_info[i].nops++] = (uint8_t)idx;
			}
			s += len;
			if (*s == ',')
				s++;
		}
	}

	const uint32_t top = 0xfff00000u;
	uint32_t total = 0;
	for (uint32_t b = 0; b < LA_NBUCKETS; b++) {
		la_bucket_start[b] = total;
		for (unsigned i = 0; i < n; i++)
			if ((((b << 20) ^ la_opcodes[i].match) & la_opcodes[i].mask & top) == 0)
				total++;
	}
	la_bucket_start[LA_NBUCKETS] = total;
	la_bucket_list = malloc((total ? total : 1) * sizeof(*la_bucket_list));
	if (!la_bucket_list)
		return false;
	uint32_t k = 0;
	for (uint32_t b = 0; b < LA_NBUCKETS; b++)
		for (unsigned i = 0; i < n; i++)
			if ((((b << 20) ^ la_opcodes[i].match) & la_opcodes[i].mask & top) == 0)
				la_bucket_list[k++] = (uint16_t)i;
	return true;
}

const char *la_name(const la_insn *insn)
{
	return la_opcodes[insn->index].name;
}

const char *la_alias(const la_insn *insn, la_operand *ops, unsigned *nops)
{
	const char *n = la_name(insn);
	const la_operand *o = insn->ops;

	if (!strcmp(n, "andi") && insn->word == 0x03400000u) {
		*nops = 0;
		return "nop";
	}
	if (!strcmp(n, "or") && o[2].value == 0) {
		ops[0] = o[0];
		ops[1] = o[1];
		*nops = 2;
		return "move";
	}
	if ((!strcmp(n, "addi.w") || !strcmp(n, "addi.d") || !strcmp(n, "ori")) && o[1].value == 0) {
		ops[0] = o[0];
		ops[1] = o[2];
		*nops = 2;
		return !strcmp(n, "addi.d") ? "li.d" : "li.w";
	}
	if (!strcmp(n, "jirl") && o[0].value == 0 && o[2].value == 0) {
		if (o[1].value == 1) {
			*nops = 0;
			return "ret";
		}
		ops[0] = o[1];
		*nops = 1;
		return "jr";
	}
	if (!strcmp(n, "blt") || !strcmp(n, "bge")) {
		bool blt = !strcmp(n, "blt");
		if (o[1].value == 0) {
			ops[0] = o[0];
			ops[1] = o[2];
			*nops = 2;
			return blt ? "bltz" : "bgez";
		}
		if (o[0].value == 0) {
			ops[0] = o[1];
			ops[1] = o[2];
			*nops = 2;
			return blt ? "bgtz" : "blez";
		}
	}
	for (unsigned i = 0; i < insn->nops; i++)
		ops[i] = o[i];
	*nops = insn->nops;
	return n;
}

uint64_t la_pcrel_value(const la_insn *insn)
{
	const char *n = la_name(insn);
	unsigned kind = 3;
	if (!strcmp(n, "pcaddi"))
		kind = 0;
	else if (!strcmp(n, "pcaddu12i"))
		kind = 1;
	else if (!strcmp(n, "pcaddu18i"))
		kind = 2;
	return la_pcrel(insn->addr, insn->ops[1].value, kind);
}
