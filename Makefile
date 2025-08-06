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
C_DEMOS := 01_generate_keys 02_encrypt 03_decrypt 04_add 05_sub 06_mul
C_EXECUTABLES := $(C_DEMOS)

# Python 3 executable
PYTHON3_EXECUTABLE := pypy

.PHONY: all build run clean

all: build run

src/core/ntt_tables.rs:
	$(PYTHON3_EXECUTABLE) devutils/gen_ntt_params.py

# Build the Rust library and the C executable
build: $(LIB_PATH)
	@mkdir -p bin
	$(foreach demo,$(C_DEMOS), \
		$(CC) demo/$(demo).c demo/run.c demo/file_io.c -I. -L$(RUST_TARGET_DIR) -lqfhe -o bin/$(demo); \
		echo "  -> C demo 'bin/$(demo)' created."; \
	)

# Build the Rust library (which also generates the header via build.rs)
$(LIB_PATH): src/lib.rs src/core/mod.rs src/hal/mod.rs src/ffi.rs Cargo.toml build.rs
	@echo "Building Rust library and generating C header..."
	CPATH="$(C_PATH)" cargo build
	@echo "Rust library '$(LIB_NAME)' built."

# Run the C executable
run-01:
	@echo "\n--- Running Demo ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/01_generate_keys ./bin/01_generate_keys
	@echo "--- End of Demo ---"

run-02:
	@echo "\n--- Running Demo ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/02_encrypt ./bin/02_encrypt
	@echo "--- End of Demo ---"

run-03:
	@echo "\n--- Running Demo ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/03_decrypt ./bin/03_decrypt
	@echo "--- End of Demo ---"

run-04:
	@echo "\n--- Running Demo ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/04_add ./bin/04_add
	@echo "--- End of Demo ---"

run-05:
	@echo "\n--- Running Demo ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/05_sub ./bin/05_sub
	@echo "--- End of Demo ---"

run-06:
	@echo "\n--- Running Demo ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./bin/06_mul ./bin/06_mul
	@echo "--- End of Demo ---"

# Clean up build artifacts
clean:
	@echo "Cleaning up build artifacts..."
	@cargo clean
	@rm -f $(C_EXECUTABLE)
	@echo "Cleanup complete."