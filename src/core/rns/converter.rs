use crate::core::u256::U256;

/// u128 정수를 RNS 표현으로 분해합니다.
pub fn integer_to_rns(val: u128, rns_basis: &[u64]) -> Vec<u64> {
    rns_basis.iter().map(|&q| (val % q as u128) as u64).collect()
}

/// 확장 유클리드 호제법
fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 { (b, 0, 1) } 
    else {
        let (g, x, y) = extended_gcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

/// 모듈러 역원 계산
fn mod_inverse(a: i128, m: i128) -> Option<i128> {
    let (g, x, _) = extended_gcd(a, m);
    if g != 1 { None } else { Some((x % m + m) % m) }
}

/// 중국인의 나머지 정리(CRT)를 사용하여 RNS 표현을 U256 정수로 재구성합니다.
pub fn rns_to_integer(rns_val: &[u64], rns_basis: &[u64]) -> U256 {
    // Q = 기저의 모든 모듈러스의 곱
    let q_product = rns_basis.iter().fold(U256::ONE, |acc, &m| acc.wrapping_mul(U256::from_u64(m)));
    let mut result = U256::ZERO;

    for (&val, &modulus) in rns_val.iter().zip(rns_basis.iter()) {
        let q_i = q_product / U256::from_u64(modulus); // Simplified division
        
        let q_i_rem = (q_i % U256::from_u64(modulus)).low as i128;
        let q_i_inv = mod_inverse(q_i_rem, modulus as i128)
            .expect("Modular inverse must exist for CRT.");

        let mut term = q_i.wrapping_mul(U256::from_u64(q_i_inv as u64));
        term = term.wrapping_mul(U256::from_u64(val));
        result = result.wrapping_add(term);
    }

    result % q_product
}
