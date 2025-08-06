# devutils/gen_ntt_params.py

import math

# ==============================================================================
# Helper Functions for Number Theory
# ==============================================================================

def power(base, exp, mod):
    """
    Calculates (base^exp) % mod efficiently.
    """
    res = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp //= 2
    return res

def modInverse(n, mod):
    """
    Calculates the modular inverse of n under mod.
    """
    return power(n, mod - 2, mod)

def find_primitive_root(p):
    """
    Finds a primitive root for a prime p.
    Note: This is a simple implementation and might be slow for very large primes.
    """
    if p == 2:
        return 1
    phi = p - 1
    
    # Find prime factors of phi
    factors = set()
    d = 2
    temp_phi = phi
    while (d * d) <= temp_phi:
        if temp_phi % d == 0:
            factors.add(d)
            while temp_phi % d == 0:
                temp_phi //= d
        d += 1
    if temp_phi > 1:
        factors.add(temp_phi)

    # Check for primitive root
    for res in range(2, p + 1):
        is_primitive = True
        for factor in factors:
            if power(res, phi // factor, p) == 1:
                is_primitive = False
                break
        if is_primitive:
            return res
    return -1

def find_optimal_factors(n):
    """
    Finds n1, n2 such that n1 * n2 = n and n1, n2 are powers of two
    and as close to sqrt(n) as possible.
    """
    if (n & (n - 1) != 0) or n == 0:
        raise ValueError("N must be a power of two.")
    k = n.bit_length() - 1
    k1 = k // 2
    k2 = k - k1
    return 1 << k1, 1 << k2

# ==============================================================================
# Rust Code Generation
# ==============================================================================

def format_rust_array(name, arr, type="u128"):
    """
    Formats a Python list into a Rust static array string.
    """
    content = f"pub const {name}: [{type}; {len(arr)}] = [\n"
    for i, val in enumerate(arr):
        content += f"    {val},"
        if (i + 1) % 8 == 0:
            content += "\n"
    if not content.endswith("\n"):
        content += "\n"
    content += "];\n"
    return content

def generate_ntt_tables_for_params(params):
    """
    Generates all necessary NTT tables for a given set of parameters.
    """
    N = params["N"]
    Q_BASIS = params["Q_BASIS"]
    
    # In an RNS system, LUTs are needed for each prime in the basis.
    # For simplicity, we generate them for the first prime, as in the Rust code.
    q = Q_BASIS[0]
    
    n1, n2 = find_optimal_factors(N)
    
    root = find_primitive_root(q)
    w_primitive = power(root, (q - 1) // N, q)
    w_inv_primitive = modInverse(w_primitive, q)

    # Generate LUTs for n1
    w_n1 = power(w_primitive, n2, q)
    w_inv_n1 = power(w_inv_primitive, n2, q)
    twiddle_lut_n1 = [power(w_n1, i, q) for i in range(n1)]
    inv_twiddle_lut_n1 = [power(w_inv_n1, i, q) for i in range(n1)]

    # Generate LUTs for n2
    w_n2 = power(w_primitive, n1, q)
    w_inv_n2 = power(w_inv_primitive, n1, q)
    twiddle_lut_n2 = [power(w_n2, i, q) for i in range(n2)]
    inv_twiddle_lut_n2 = [power(w_inv_n2, i, q) for i in range(n2)]

    # Generate matrix twiddles
    twiddle_matrix = [power(w_primitive, i * j, q) for i in range(n1) for j in range(n2)]
    inv_twiddle_matrix = [power(w_inv_primitive, i * j, q) for i in range(n1) for j in range(n2)]

    # --- Generate Rust code string ---
    code = f"// NTT Tables for N={N}, Q={q}\n"
    code += format_rust_array(f"TWIDDLE_LUT_N1_{N}", twiddle_lut_n1)
    code += format_rust_array(f"TWIDDLE_LUT_N2_{N}", twiddle_lut_n2)
    code += format_rust_array(f"INV_TWIDDLE_LUT_N1_{N}", inv_twiddle_lut_n1)
    code += format_rust_array(f"INV_TWIDDLE_LUT_N2_{N}", inv_twiddle_lut_n2)
    code += format_rust_array(f"TWIDDLE_MATRIX_{N}", twiddle_matrix)
    code += format_rust_array(f"INV_TWIDDLE_MATRIX_{N}", inv_twiddle_matrix)
    
    return code

# ==============================================================================
# Main Execution
# ==============================================================================

if __name__ == "__main__":
    # Parameters mirroring src/core/rns.rs and src/core/mod.rs
    PARAMS_1024 = {
        "N": 1024,
        "Q_BASIS": [1152921504606584833], # Q_128_BASIS
    }
    
    PARAMS_2048 = {
        "N": 2048,
        "Q_BASIS": [9223372036854775783], # First element of Q_224_BASIS
    }

    # Generate the full Rust file content
    rust_file_content = "// devutils/gen_ntt_params.py로 자동 생성된 파일입니다.\n"
    rust_file_content += "// 수동으로 편집하지 마세요.\n\n"
    rust_file_content += "#![allow(clippy::all)]\n\n"
    
    rust_file_content += "pub mod n1024 {\n"
    rust_file_content += generate_ntt_tables_for_params(PARAMS_1024)
    rust_file_content += "}\n\n"

    rust_file_content += "pub mod n2048 {\n"
    rust_file_content += generate_ntt_tables_for_params(PARAMS_2048)
    rust_file_content += "}\n"

    # Write to file
    output_path = "src/core/consts/ntt_tables.rs"
    try:
        with open(output_path, "w") as f:
            f.write(rust_file_content)
        print(f"Successfully generated NTT tables at: {output_path}")
    except IOError as e:
        print(f"Error writing to file {output_path}: {e}")

