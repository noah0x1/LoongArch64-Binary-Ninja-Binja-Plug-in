#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
TAGS=${TAGS:-"stable/5.2.8722 stable/5.3.9757 stable/6.0.10601"}
CC=${CC:-cc}
for tag in $TAGS; do
	w=build/prebuilt/$(echo "$tag" | tr / _)
	rm -rf "$w"
	mkdir -p "$w/api" "$w/obj" "$w/core"
	curl -fsSL -o "$w/api/binaryninjacore.h" \
		"https://raw.githubusercontent.com/Vector35/binaryninja-api/refs/tags/$tag/binaryninjacore.h"
	abi=$(awk '/define BN_CURRENT_CORE_ABI_VERSION/ {print $3; exit}' "$w/api/binaryninjacore.h")
	for f in src/*.c src/decode.S; do
		$CC -std=c11 -O2 -fPIC -fvisibility=hidden -Wall -Wextra -Iinclude -isystem "$w/api" \
			-c "$f" -o "$w/obj/$(basename "$f").o"
	done
	nm -u "$w"/obj/*.o | awk '$1 == "U" && $2 ~ /^BN/ {print "void " $2 "(void) {}"}' | sort -u > "$w/core/stubs.c"
	$CC -shared -fPIC -Wl,-soname,libbinaryninjacore.so.1 -o "$w/core/libbinaryninjacore.so.1" "$w/core/stubs.c"
	mkdir -p "native/abi$abi"
	$CC -shared -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -Wl,--no-undefined \
		-o "native/abi$abi/libarch_la64.so" "$w"/obj/*.o -L"$w/core" -l:libbinaryninjacore.so.1
	strip --strip-unneeded "native/abi$abi/libarch_la64.so"
	echo "native/abi$abi/libarch_la64.so ($tag)"
done
