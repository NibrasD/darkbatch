//! Real Pallas Elliptic Curve Cryptography for Zcash NU6.3 / Ironwood
//! Uses pasta_curves for genuine point arithmetic on y^2 = x^3 + 5 over Fp.

use group::{Group, GroupEncoding};
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas::{Point, Scalar};
use blake2b_simd::Params;

/// Fixed Pallas generator points derived per Zcash Protocol Specification § 5.4.9.4:
/// V_Orchard = GroupHash^P("z.cash:Orchard-cv", "v")
/// R_Orchard = GroupHash^P("z.cash:Orchard-cv", "r")
pub fn generator_v() -> Point {
    Point::hash_to_curve("z.cash:Orchard-cv")(b"v")
}

pub fn generator_r() -> Point {
    Point::hash_to_curve("z.cash:Orchard-cv")(b"r")
}

pub fn generator_g() -> Point {
    Point::generator()
}

/// Computes a true Pedersen Value Commitment on the Pallas curve:
/// C = [v] * V + [r] * R
pub fn pedersen_commit(value: u64, r: &Scalar) -> Point {
    let v_scalar = Scalar::from(value);
    let v_point = generator_v() * v_scalar;
    let r_point = generator_r() * r;
    v_point + r_point
}

/// Verifies additive value commitment balance conservation:
/// sum(C_in) - sum(C_out) == [value_balance] * V + [bsk_bundle] * R
pub fn verify_value_balance(
    inputs: &[Point],
    outputs: &[Point],
    value_balance: i64,
    bsk_bundle: &Scalar,
) -> bool {
    let sum_in: Point = inputs.iter().copied().sum();
    let sum_out: Point = outputs.iter().copied().sum();
    let net_commit = sum_in - sum_out;

    let v_term = if value_balance >= 0 {
        generator_v() * Scalar::from(value_balance as u64)
    } else {
        -(generator_v() * Scalar::from((-value_balance) as u64))
    };

    let r_term = generator_r() * bsk_bundle;
    let expected = v_term + r_term;

    net_commit == expected
}

use ff::PrimeField;

/// Generates a random Pallas scalar for blinding or secret keys
pub fn random_scalar() -> Scalar {
    use rand::Rng;
    let mut bytes = [0u8; 64];
    rand::rng().fill_bytes(&mut bytes);
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"DarkBatchScalarR")
        .to_state()
        .update(&bytes)
        .finalize();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(h.as_bytes());
    repr[31] &= 0x3f; // mask to fit within Pallas field order
    Scalar::from_repr(repr).unwrap_or(Scalar::one())
}

/// Deterministically decodes 32 bytes into a valid Pallas scalar
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Scalar {
    let mut repr = *bytes;
    repr[31] &= 0x3f; // mask to fit within Pallas field order
    Scalar::from_repr(repr).unwrap_or(Scalar::one())
}

/// Computes RedPallas randomized spend authorization validating key:
/// rk = [alpha] * G + ak
pub fn derive_randomized_key(ak: &Point, alpha: &Scalar) -> Point {
    ak + (generator_g() * alpha)
}

/// Derives deterministic nullifier using Pallas and Blake2b
pub fn derive_nullifier(nk: &Point, position: u64, cm: &Point) -> [u8; 32] {
    let mut state = Params::new()
        .hash_length(32)
        .personal(b"IronwoodNullifer")
        .to_state();
    state.update(&nk.to_bytes());
    state.update(&position.to_le_bytes());
    state.update(&cm.to_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_homomorphism() {
        let r1 = random_scalar();
        let r2 = random_scalar();
        let v1 = 50_000_000u64;
        let v2 = 30_000_000u64;

        let c1 = pedersen_commit(v1, &r1);
        let c2 = pedersen_commit(v2, &r2);

        let c_sum = c1 + c2;
        let r_sum = r1 + r2;
        let c_expected = pedersen_commit(v1 + v2, &r_sum);

        assert_eq!(c_sum, c_expected);
    }

    #[test]
    fn test_value_balance_conservation() {
        let r_in = random_scalar();
        let r_out = random_scalar();
        let c_in = pedersen_commit(100, &r_in);
        let c_out = pedersen_commit(100, &r_out);

        let bsk_bundle = r_in - r_out;
        assert!(verify_value_balance(&[c_in], &[c_out], 0, &bsk_bundle));
    }
}
