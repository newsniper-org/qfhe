// src/hal/cpu/ntt.rs
use num_complex::Complex;
use crate::core::QfheParameters; // QfheParameters를 직접 사용

// u64 모듈러 거듭제곱 (a^b % m)
fn power(mut a: u64, mut b: u64, m: u64) -> u64 {
    let mut res = 1;
    a %= m;
    while b > 0 {
        if b % 2 == 1 {
            res = ((res as u128 * a as u128) % m as u128) as u64;
        }
        b >>= 1;
        a = ((a as u128 * a as u128) % m as u128) as u64;
    }
    res
}

/// u64 모듈러 곱셈 역원 (a^-1 % m)
fn mod_inverse(n: u64, m: u64) -> u64 {
    power(n, m - 2, m)
}

/// 주어진 NTT 파라미터에 맞는 원시근(primitive root)을 찾는 함수.
/// 실제 라이브러리에서는 미리 계산된 값을 사용하지만, 여기서는 간단한 검색으로 찾습니다.
fn find_primitive_root(n: u64, modulus: u64) -> u64 {
    // 2N-th root of unity가 필요함
    let phi = modulus - 1;
    let required_order = 2 * n;
    if phi % required_order != 0 {
        panic!("Modulus does not support the required root of unity.");
    }

    let mut g = 2;
    loop {
        if power(g, phi / 2, modulus) != 1 {
            if power(g, phi / required_order, modulus) != 1 { // 추가 조건으로 더 적절한 root 찾기
                 break;
            }
        }
        g += 1;
    }
    power(g, phi / required_order, modulus)
}


/// NTT 연산을 위한 사전 계산된 값들을 저장하는 구조체
pub struct NttOperator {
    n: usize,
    modulus: u64,
    roots_of_unity: Vec<Complex<u64>>,
    inv_roots_of_unity: Vec<Complex<u64>>,
    inv_n: Complex<u64>,
}

impl NttOperator {
    /// 주어진 파라미터로 새로운 NTT 연산자를 생성
    pub fn new(params: &QfheParameters) -> Self {
        let n = params.polynomial_degree;
        let modulus = params.modulus_q as u64; // u128을 u64로 변환

        let root = find_primitive_root(n as u64, modulus);
        let inv_root = mod_inverse(root, modulus);

        let mut roots = vec![Complex::new(0, 0); n];
        let mut inv_roots = vec![Complex::new(0, 0); n];

        let mut current_root: u64 = 1;
        let mut current_inv_root: u64 = 1;

        for i in 0..n {
            roots[i] = Complex::new(current_root, 0);
            inv_roots[i] = Complex::new(current_inv_root, 0);
            current_root = (current_root as u128 * root as u128 % modulus as u128) as u64;
            current_inv_root = (current_inv_root as u128 * inv_root as u128 % modulus as u128) as u64;
        }

        Self {
            n,
            modulus,
            roots_of_unity: roots,
            inv_roots_of_unity: inv_roots,
            inv_n: Complex::new(mod_inverse(n as u64, modulus), 0),
        }
    }
}

/// 비트 반전 순서로 배열을 재정렬 (In-place)
fn bit_reverse_permutation(a: &mut [Complex<u64>]) {
    let n = a.len();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while (j & bit) != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }
}

/// Cooley-Tukey FFT 알고리즘 (NTT)
fn ntt_recursive(a: &mut [Complex<u64>], op: &NttOperator, inverse: bool) {
    let n = op.n;
    if a.len() != n { panic!("Input size does not match NTT operator size."); }

    bit_reverse_permutation(a);

    let roots = if inverse { &op.inv_roots_of_unity } else { &op.roots_of_unity };
    let modulus = op.modulus;

    let mut len = 2;
    while len <= n {
        let step = n / len;
        for i in 0..n / len {
            for j in 0..len / 2 {
                let root_idx = j * step;
                let root = roots[root_idx];
                let u = a[i * len + j];
                let v_re = (a[i * len + j + len / 2].re as u128 * root.re as u128) % modulus as u128;
                let v = Complex::new(v_re as u64, 0);

                a[i * len + j].re = (u.re + v.re) % modulus;
                a[i * len + j + len / 2].re = (u.re + modulus - v.re) % modulus;
            }
        }
        len <<= 1;
    }
}


/// 순방향 NTT
pub fn forward_ntt(op: &NttOperator, p: &mut Vec<Complex<u64>>) {
    ntt_recursive(p, op, false);
}

/// 역방향 NTT
pub fn inverse_ntt(op: &NttOperator, p: &mut Vec<Complex<u64>>) {
    ntt_recursive(p, op, true);
    for val in p.iter_mut() {
        val.re = (val.re as u128 * op.inv_n.re as u128 % op.modulus as u128) as u64;
    }
}

/// 점-값 표현에서 다항식 곱셈 (Element-wise)
pub fn multiply_pointwise(a: &[Complex<u64>], b: &[Complex<u64>], modulus: u64) -> Vec<Complex<u64>> {
    a.iter()
        .zip(b.iter())
        .map(|(c1, c2)| {
            let re = (c1.re as u128 * c2.re as u128) % modulus as u128;
            Complex::new(re as u64, 0)
        })
        .collect()
}