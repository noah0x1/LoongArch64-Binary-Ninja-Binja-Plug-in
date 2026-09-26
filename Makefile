BN_INSTALL ?= $(HOME)/binaryninja
BN_API     ?= third_party
PLUGIN_DIR ?= $(HOME)/.binaryninja/plugins

CFLAGS    ?= -O2
LA_CFLAGS := -std=c11 -fPIC -fvisibility=hidden -Wall -Wextra -Iinclude -isystem $(BN_API)
LA_LDFLAGS := -shared -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now

CORE_LIB := $(wildcard $(BN_INSTALL)/libbinaryninjacore.so.1)
ifneq ($(CORE_LIB),)
LA_LIBS := -L$(BN_INSTALL) -l:libbinaryninjacore.so.1 -Wl,-rpath,$(BN_INSTALL) -Wl,--no-undefined
endif

SRC    := src/plugin.c src/arch.c src/cc.c src/lift.c src/plt.c src/ladis.c src/opcodes.c src/decode.S
OBJ    := $(patsubst src/%,build/%.o,$(SRC))
TARGET := build/libarch_la64.so
HDRS   := include/la64.h include/la64_bn.h $(BN_API)/binaryninjacore.h

.PHONY: all install uninstall header prebuilt clean distclean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LA_LDFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LA_LIBS) $(LDLIBS)
	@echo "built: $@"
ifeq ($(CORE_LIB),)
	@echo "note: $(BN_INSTALL)/libbinaryninjacore.so.1 not found, linked without the core (this works too)."
endif

build/%.c.o: src/%.c $(HDRS) | build
	$(CC) $(LA_CFLAGS) $(CFLAGS) -c $< -o $@

build/%.S.o: src/%.S include/la64.h | build
	$(CC) $(LA_CFLAGS) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

third_party/binaryninjacore.h:
	$(MAKE) header

header:
	@rev=$$(grep -oE '[0-9a-f]{40}' "$(BN_INSTALL)/api_REVISION.txt" 2>/dev/null | head -n 1); \
	if [ -z "$$rev" ]; then \
		echo "No commit hash found in $(BN_INSTALL)/api_REVISION.txt."; \
		echo "Set BN_INSTALL=/path/to/binaryninja or BN_API=/path/to/binaryninja-api."; \
		exit 1; \
	fi; \
	mkdir -p third_party; \
	curl -fsSL -o third_party/binaryninjacore.h \
		"https://raw.githubusercontent.com/Vector35/binaryninja-api/$$rev/binaryninjacore.h" && \
	echo "fetched binaryninjacore.h for binaryninja-api@$$rev, ABI version:" && \
	grep -m1 'define BN_CURRENT_CORE_ABI_VERSION' third_party/binaryninjacore.h

install: $(TARGET)
	mkdir -p "$(PLUGIN_DIR)"
	install -m 755 $(TARGET) "$(PLUGIN_DIR)/"
	@echo "installed to $(PLUGIN_DIR). Remove or disable the Python version of the plugin first!"

uninstall:
	rm -f "$(PLUGIN_DIR)/libarch_la64.so"

prebuilt:
	sh tools/build_prebuilt.sh

clean:
	rm -rf build

distclean: clean
	rm -rf third_party
