# Makefile for building and running the QFHE demo

# Rust target directory
RUST_TARGET_DIR := target/debug

# Name of the Rust dynamic library
# Note: Naming conventions differ by OS (e.g., libqfhe.so on Linux, libqfhe.dylib on macOS, qfhe.dll on Windows)
ifeq ($(OS),Windows_NT)
    LIB_NAME := qfhe.dll
    LIB_PATH := $(RUST_TARGET_DIR)/$(LIB_NAME)
    C_COMPILER := gcc
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        LIB_NAME := libqfhe.so
        LIB_PATH := $(RUST_TARGET_DIR)/$(LIB_NAME)
        C_COMPILER := gcc
    endif
    ifeq ($(UNAME_S),Darwin)
        LIB_NAME := libqfhe.dylib
        LIB_PATH := $(RUST_TARGET_DIR)/$(LIB_NAME)
        C_COMPILER := clang
    endif
endif

# C source and executable
C_SOURCE := demo/main.c
C_EXECUTABLE := main_demo
C_PATH := /usr/lib/gcc/x86_64-redhat-linux/15/include/

.PHONY: all build run clean

all: run

# Build the Rust library and the C executable
build: $(LIB_PATH)
	$(C_COMPILER) $(C_SOURCE) -I. -L$(RUST_TARGET_DIR) -lqfhe -o $(C_EXECUTABLE)
	@echo "\nC executable '$(C_EXECUTABLE)' created."

# Build the Rust library (which also generates the header via build.rs)
$(LIB_PATH): src/lib.rs src/core/mod.rs src/hal/mod.rs src/ffi.rs Cargo.toml build.rs
	@echo "Building Rust library and generating C header..."
	CPATH="$(C_PATH)" cargo build
	@echo "Rust library '$(LIB_NAME)' built."

# Run the C executable
run:
	@echo "\n--- Running Demo ---"
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) DYLD_LIBRARY_PATH=$(RUST_TARGET_DIR)./$(C_EXECUTABLE) ./$(C_EXECUTABLE)
	@echo "--- End of Demo ---"

# Clean up build artifacts
clean:
	@echo "Cleaning up build artifacts..."
	@cargo clean
	@rm -f $(C_EXECUTABLE)
	@echo "Cleanup complete."