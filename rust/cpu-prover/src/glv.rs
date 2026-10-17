//! Fixed-width BN254 lattice decomposition. Quotients use fixed reciprocals;
//! exact rounding is unnecessary because each lattice row is zero mod r.
use ark_bn254::{g1, g2, Fr};
use ark_ec::scalar_mul::glv::GLVConfig;
use ark_ff::BigInteger256;

pub(super) trait Bn254Glv: GLVConfig<ScalarField = Fr> {
    const RECIP_N22: [u32; 8];
}
impl Bn254Glv for g1::Config {
    const RECIP_N22: [u32; 8] = [16737637, 1402535171, 2809385682, 1288630292, 2, 0, 0, 0];
}
impl Bn254Glv for g2::Config {
    const RECIP_N22: [u32; 8] = [958312845, 2054937044, 2809385679, 1288630292, 2, 0, 0, 0];
}
const RECIP_N12: [u32; 8] = [3353392087, 3642565422, 2, 0, 0, 0, 0, 0];

type Words = [u32; 16];

fn words(k: BigInteger256) -> [u32; 8] {
    core::array::from_fn(|i| (k.0[i / 2] >> ((i % 2) * 32)) as u32)
}

fn multiply(a: [u32; 8], b: [u32; 8]) -> Words {
    let mut out = [0u32; 16];
    let a_len = a.iter().rposition(|v| *v != 0).map_or(0, |i| i + 1);
    let b_len = b.iter().rposition(|v| *v != 0).map_or(0, |i| i + 1);
    for (i, a) in a.into_iter().take(a_len).enumerate() {
        let mut carry = 0u64;
        for (j, b) in b.iter().take(b_len).enumerate() {
            // (2^32-1)^2 + (2^32-1) + (2^32-1) = 2^64-1.
            let value = u64::from(a) * u64::from(*b) + u64::from(out[i + j]) + carry;
            out[i + j] = value as u32;
            carry = value >> 32;
        }
        out[i + b_len] = carry as u32;
    }
    out
}

fn quotient(k: [u32; 8], reciprocal: [u32; 8]) -> [u32; 8] {
    let product = multiply(k, reciprocal);
    core::array::from_fn(|i| product[i + 8])
}

#[derive(Clone, Copy)]
struct Signed {
    positive: bool,
    words: Words,
}
impl Signed {
    fn add(self, rhs: Self) -> Self {
        if self.positive == rhs.positive {
            let mut carry = 0u64;
            let words = core::array::from_fn(|i| {
                let v = u64::from(self.words[i]) + u64::from(rhs.words[i]) + carry;
                carry = v >> 32;
                v as u32
            });
            Self {
                positive: self.positive,
                words,
            }
        } else {
            let (hi, lo) = if self.words.iter().rev().cmp(rhs.words.iter().rev()).is_ge() {
                (self, rhs)
            } else {
                (rhs, self)
            };
            let mut borrow = false;
            let words = core::array::from_fn(|i| {
                let (v, first) = hi.words[i].overflowing_sub(lo.words[i]);
                let (v, second) = v.overflowing_sub(u32::from(borrow));
                borrow = first || second;
                v
            });
            Self {
                positive: hi.positive,
                words,
            }
        }
    }
    fn negate(self) -> Self {
        Self {
            positive: !self.positive,
            ..self
        }
    }
    fn bigint(self) -> (bool, BigInteger256) {
        // For k < 2^256 the reciprocal quotient error is <1. Each component
        // is bounded by sums of at most four 128-bit lattice coefficients;
        // hence <2^130, and the upper eight words are zero.
        (
            self.positive,
            BigInteger256::new(core::array::from_fn(|i| {
                u64::from(self.words[2 * i]) | (u64::from(self.words[2 * i + 1]) << 32)
            })),
        )
    }
}

pub(super) fn decompose<P: Bn254Glv>(
    k: BigInteger256,
) -> ((bool, BigInteger256), (bool, BigInteger256)) {
    let k = words(k);
    let n = P::SCALAR_DECOMP_COEFFS;
    let beta1 = quotient(k, P::RECIP_N22);
    let beta2 = quotient(k, RECIP_N12);
    // beta1 has sign(n22); beta2 has sign(-n12).
    let b11 = Signed {
        positive: n[3].0 == n[0].0,
        words: multiply(beta1, words(n[0].1)),
    };
    let b12 = Signed {
        positive: n[1].0 != n[2].0,
        words: multiply(beta2, words(n[2].1)),
    };
    let b21 = Signed {
        positive: n[3].0 == n[1].0,
        words: multiply(beta1, words(n[1].1)),
    };
    let b22 = Signed {
        positive: n[1].0 != n[3].0,
        words: multiply(beta2, words(n[3].1)),
    };
    let mut k_full = [0; 16];
    k_full[..8].copy_from_slice(&k);
    let k1 = Signed {
        positive: true,
        words: k_full,
    }
    .add(b11.negate())
    .add(b12.negate());
    let k2 = b21.add(b22).negate();
    (k1.bigint(), k2.bigint())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/unit/glv.rs"]
mod tests;
