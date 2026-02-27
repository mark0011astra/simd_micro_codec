CC ?= clang

CFLAGS_COMMON := -std=c11 -D_POSIX_C_SOURCE=200809L -Iinclude -Wall -Wextra -Werror -pedantic
CFLAGS_RELEASE := -O3
CFLAGS_TEST := -O2
CFLAGS_DEBUG := -O0 -g3
SAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer
THREAD_FLAGS := -pthread

.PHONY: all clean unit fuzz test bench bench-compare sanitize static-analysis check-no-dynamic compile-x86

all: test

build:
	mkdir -p build

build/test_smc_hex: tests/test_smc_hex.c src/smc_hex.c include/smc_hex.h | build
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_TEST) tests/test_smc_hex.c src/smc_hex.c -o $@

build/test_fuzz: tests/test_fuzz.c src/smc_hex.c include/smc_hex.h | build
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_TEST) tests/test_fuzz.c src/smc_hex.c -o $@

build/test_thread_init: tests/test_thread_init.c src/smc_hex.c include/smc_hex.h | build
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_TEST) $(THREAD_FLAGS) tests/test_thread_init.c src/smc_hex.c -o $@

build/bench: bench/bench.c src/smc_hex.c include/smc_hex.h | build
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_RELEASE) bench/bench.c src/smc_hex.c -o $@

build/bench_compare: bench/bench_compare.c src/smc_hex.c include/smc_hex.h | build
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_RELEASE) bench/bench_compare.c src/smc_hex.c -o $@ $$(pkg-config --cflags --libs openssl)

unit: build/test_smc_hex build/test_thread_init

fuzz: build/test_fuzz

bench: build/bench

bench-compare: build/bench_compare

check-no-dynamic:
	@if rg -n "\\b(malloc|calloc|realloc|free)\\s*\\(" src include; then \
		echo "dynamic memory usage found in library sources"; \
		exit 1; \
	fi

test: unit fuzz check-no-dynamic
	./build/test_smc_hex
	./build/test_thread_init
	./build/test_fuzz

build/test_smc_hex_san: tests/test_smc_hex.c src/smc_hex.c include/smc_hex.h | build
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(SAN_FLAGS) tests/test_smc_hex.c src/smc_hex.c -o $@

build/test_fuzz_san: tests/test_fuzz.c src/smc_hex.c include/smc_hex.h | build
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(SAN_FLAGS) tests/test_fuzz.c src/smc_hex.c -o $@

build/test_thread_init_san: tests/test_thread_init.c src/smc_hex.c include/smc_hex.h | build
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(SAN_FLAGS) $(THREAD_FLAGS) tests/test_thread_init.c src/smc_hex.c -o $@

sanitize: build/test_smc_hex_san build/test_fuzz_san build/test_thread_init_san
	ASAN_OPTIONS=detect_leaks=0 ./build/test_smc_hex_san
	ASAN_OPTIONS=detect_leaks=0 ./build/test_thread_init_san
	ASAN_OPTIONS=detect_leaks=0 ./build/test_fuzz_san

static-analysis:
	@set -e; \
	for f in src/smc_hex.c tests/test_smc_hex.c tests/test_fuzz.c tests/test_thread_init.c bench/bench.c; do \
		out=$$(mktemp); \
		$(CC) $(CFLAGS_COMMON) --analyze -Xanalyzer -analyzer-output=text "$$f" >"$$out" 2>&1 || { cat "$$out"; rm -f "$$out"; exit 1; }; \
		if rg -n "warning:" "$$out" >/dev/null; then \
			cat "$$out"; \
			rm -f "$$out"; \
			echo "static analysis failed for $$f"; \
			exit 1; \
		fi; \
		rm -f "$$out"; \
	done

compile-x86: | build
	$(CC) $(CFLAGS_COMMON) -target x86_64-apple-macos13 -c src/smc_hex.c -o build/smc_hex_x86.o

clean:
	rm -rf build
