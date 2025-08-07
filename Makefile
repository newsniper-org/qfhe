# Makefile for building and running the QFHE demo

# Rust target directory
RUST_TARGET_DIR := target/debug

# Name of the Rust dynamic library
# Note: Naming conventions differ by OS (e.g., libqfhe.so on Linux, libqfhe.dylib on macOS, qfhe.dll on Windows)
ifeq ($(OS),Windows_NT)
    LIB_NAME := qfhe.dll
    LIB_PATH := $(RUST_TARGET_DIR)/$(LIB_NAME)
    CC := gcc
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        LIB_NAME := libqfhe.so
        LIB_PATH := $(RUST_TARGET_DIR)/$(LIB_NAME)
        CC := gcc
    endif
    ifeq ($(UNAME_S),Darwin)
        LIB_NAME := libqfhe.dylib
        LIB_PATH := $(RUST_TARGET_DIR)/$(LIB_NAME)
        CC := clang
    endif
endif

# C source and executable
C_PATH := /usr/lib/gcc/x86_64-redhat-linux/15/include/
C_DEMOS := 01_generate_keys 02_encrypt 03_decrypt 04_add 05_mul 06_bootstrap
C_EXECUTABLES := $(C_DEMOS)

# Python 3 executable
PYTHON3_EXECUTABLE := pypy

.PHONY: all build run clean

all: demo

src/core/ntt_tables.rs:
	$(PYTHON3_EXECUTABLE) devutils/gen_ntt_params.py

# Build the Rust library and the C executable
build: $(LIB_PATH)
	@mkdir -p bin/debug
	$(foreach demo,$(C_DEMOS), \
		$(CC) demo/$(demo).c demo/file_io.c -I. -L$(RUST_TARGET_DIR) -lqfhe -o bin/debug/$(demo); \
		echo "  -> C demo 'bin/debug/$(demo)' created."; \
	)

# Build the Rust library (which also generates the header via build.rs)
$(LIB_PATH): src/lib.rs src/core/mod.rs src/hal/mod.rs src/ffi.rs Cargo.toml build.rs
	@echo "Building Rust library and generating C header..."
	CPATH="$(C_PATH)" cargo build
	@echo "Rust library '$(LIB_NAME)' built."

# A full demonstration flow
demo: build
	@mkdir -p demo_output
	@echo "\n--- 1. Generating Keys ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/debug/01_generate_keys ./bin/debug/01_generate_keys
	@echo "\n--- 2. Encrypting 42 and 10 ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/debug/02_encrypt ./bin/debug/02_encrypt demo_output/qfhe128.pk 42 demo_output/ct_42.ct
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/debug/02_encrypt ./bin/debug/02_encrypt demo_output/qfhe128.pk 10 demo_output/ct_10.ct
	@echo "\n--- 3. Decrypting 42 to verify ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/debug/03_decrypt ./bin/debug/03_decrypt demo_output/ct_42.ct demo_output/qfhe128.sk
	@echo "\n--- 4. Homomorphic Addition (42 + 10 = 52) ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/debug/04_add ./bin/debug/04_add demo_output/ct_42.ct demo_output/ct_10.ct demo_output/ct_add_52.ct
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/debug/03_decrypt ./bin/debug/03_decrypt demo_output/ct_add_52.ct demo_output/qfhe128.sk
	@echo "\n--- 5. Homomorphic Multiplication (52 * 10 = 520) ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/debug/05_mul ./bin/debug/05_mul demo_output/ct_add_52.ct demo_output/ct_10.ct demo_output/qfhe128.rlk demo_output/ct_mul_520.ct
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/debug/03_decrypt ./bin/debug/03_decrypt demo_output/ct_mul_520.ct demo_output/qfhe128.sk
	@echo "\n--- 6. Bootstrapping (f(520) = 2*520 = 1040) ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/debug/06_bootstrap ./bin/debug/06_bootstrap demo_output/ct_mul_520.ct demo_output/qfhe128.sk demo_output/qfhe128.bk demo_output/ct_pbs_1040.ct

# Clean up build artifacts
clean-bin:
	@echo "Cleaning up bin/debug ..."
	@cargo clean
	@rm -rf bin/debug
	@echo "Cleanup complete."

# Clean up demonstration outputs.
clean-output:
	@echo "Cleaning up demo_output ..."
	@rm -rf demo_output
	@echo "Cleanup complete."

clean: clean-output clean-bin