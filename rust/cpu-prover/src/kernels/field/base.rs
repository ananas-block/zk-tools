//! Portable nine-limb BN254 base-field arithmetic, R=2^261.
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
use super::simd;
use super::SmallField;
use ark_bn254::Fq;
use ark_ff::{BigInt, BigInteger, BigInteger256, Field, PrimeField};
use core::ops::{Add, Mul, Neg, Sub};

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[cfg(feature = "wasm")]
#[cfg(feature = "test-support")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name=wasmArithmeticSelfTest)]
pub fn simd_self_test(seed: u32, count: u32) -> bool {
    simd::self_test(seed, count)
}

#[cfg(all(
    target_arch = "wasm32",
    target_feature = "simd128",
    feature = "wasm",
    feature = "test-support"
))]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = wasmBaseFieldFixture)]
pub fn base_field_fixture(a: &[u8], b: &[u8]) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
    if a.len() != 32 || b.len() != 32 {
        return Err(wasm_bindgen::JsValue::from_str(
            "base field fixtures require two 32-byte inputs",
        ));
    }
    let a = F9::encode(Fq::from_le_bytes_mod_order(a));
    let b = F9::encode(Fq::from_le_bytes_mod_order(b));
    let (product, square) = F9::pair_mul(a, a, b, a);
    let mut result = product.decode().into_bigint().to_bytes_le();
    result.extend(square.decode().into_bigint().to_bytes_le());
    Ok(result)
}

pub(in crate::kernels) const MASK: u64 = (1 << 29) - 1;
pub(in crate::kernels) const Q: [u32; 9] = split(Fq::MODULUS);
pub(in crate::kernels) const INV: u64 = <ark_bn254::FqConfig as ark_ff::MontConfig<4>>::INV & MASK;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::kernels) struct F9(pub(in crate::kernels) [u32; 9]);

const fn split(a: BigInteger256) -> [u32; 9] {
    [
        (a.0[0] & MASK) as u32,
        ((a.0[0] >> 29) & MASK) as u32,
        (((a.0[0] >> 58) | (a.0[1] << 6)) & MASK) as u32,
        ((a.0[1] >> 23) & MASK) as u32,
        (((a.0[1] >> 52) | (a.0[2] << 12)) & MASK) as u32,
        ((a.0[2] >> 17) & MASK) as u32,
        (((a.0[2] >> 46) | (a.0[3] << 18)) & MASK) as u32,
        ((a.0[3] >> 11) & MASK) as u32,
        (a.0[3] >> 40) as u32,
    ]
}

impl F9 {
    // This const conversion runs at compile time for ONE, and only once per
    // coordinate when loading a proving-key point into this backend.
    pub(in crate::kernels) const fn encode(value: Fq) -> Self {
        let q = Fq::MODULUS.0;
        let mut limbs = value.0 .0;
        let mut n = 0;
        while n < 5 {
            let mut carry = 0u128;
            let mut i = 0;
            while i < 4 {
                carry += (limbs[i] as u128) * 2;
                limbs[i] = carry as u64;
                carry >>= 64;
                i += 1;
            }
            let mut geq = true;
            let mut i = 4;
            while i > 0 {
                i -= 1;
                if limbs[i] != q[i] {
                    geq = limbs[i] > q[i];
                    break;
                }
            }
            if geq {
                let mut borrow = false;
                let mut i = 0;
                while i < 4 {
                    let (v, b1) = limbs[i].overflowing_sub(q[i]);
                    let (v, b2) = v.overflowing_sub(borrow as u64);
                    limbs[i] = v;
                    borrow = b1 || b2;
                    i += 1;
                }
            }
            n += 1;
        }
        Self(split(BigInt(limbs)))
    }

    pub(in crate::kernels) fn decode(self) -> Fq {
        let a = self.reduce().0.map(u64::from);
        let mut raw = BigInt([
            a[0] | (a[1] << 29) | (a[2] << 58),
            (a[2] >> 6) | (a[3] << 23) | (a[4] << 52),
            (a[4] >> 12) | (a[5] << 17) | (a[6] << 46),
            (a[6] >> 18) | (a[7] << 11) | (a[8] << 40),
        ]);
        for _ in 0..5 {
            if raw.is_odd() {
                raw.add_with_carry(&Fq::MODULUS);
            }
            raw.div2();
        }
        Fq::new_unchecked(raw)
    }

    #[inline(always)]
    fn reduce(self) -> Self {
        self.reduce_to(&Q)
    }
    #[inline(always)]
    fn reduce_to(mut self, limit: &[u32; 9]) -> Self {
        let mut geq = true;
        for i in (0..9).rev() {
            if self.0[i] != limit[i] {
                geq = self.0[i] > limit[i];
                break;
            }
        }
        if geq {
            let mut borrow = 0i64;
            for i in 0..9 {
                let v = i64::from(self.0[i]) - i64::from(limit[i]) + borrow;
                self.0[i] = (v as u64 & MASK) as u32;
                borrow = v >> 29;
            }
        }
        self
    }

    /// M=1 or2, with reduced inputs. Every delayed coefficient is below
    /// 27*2^58 plus carries, hence below2^63. The final value is below2q.
    #[inline(always)]
    fn products<const M: usize>(a: [Self; M], b: [Self; M]) -> Self {
        let b = b.map(|value| value.0.map(u64::from));
        let mut t = [0u64; 9];
        for i in 0..9 {
            let mut lo = t[0];
            for (a, b) in a.iter().zip(&b) {
                lo += u64::from(a.0[i]) * b[0];
            }
            let m = lo.wrapping_mul(INV) & MASK;
            let carry = (lo + m * u64::from(Q[0])) >> 29;
            for j in 1..9 {
                let mut v = t[j] + m * u64::from(Q[j]);
                for (a, b) in a.iter().zip(&b) {
                    v += u64::from(a.0[i]) * b[j];
                }
                if j == 1 {
                    v += carry;
                }
                t[j - 1] = v;
            }
            t[8] = 0;
        }
        let mut out = [0u32; 9];
        let mut carry = 0;
        for (out, t) in out.iter_mut().zip(t) {
            let v = t + carry;
            *out = (v & MASK) as u32;
            carry = v >> 29;
        }

        {
            Self(out).reduce()
        }
    }
}

impl Add for F9 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut out = [0u32; 9];
        let mut carry = 0u64;
        for i in 0..9 {
            let v = u64::from(self.0[i]) + u64::from(rhs.0[i]) + carry;
            out[i] = (v & MASK) as u32;
            carry = v >> 29;
        }

        {
            Self(out).reduce()
        }
    }
}
impl Sub for F9 {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        let mut out = [0u32; 9];
        let mut borrow = 0i64;
        for i in 0..9 {
            let v = i64::from(self.0[i]) - i64::from(rhs.0[i]) + borrow;
            out[i] = (v as u64 & MASK) as u32;
            borrow = v >> 29;
        }
        if borrow != 0 {
            let modulus = &Q;
            let mut carry = 0u64;
            for i in 0..9 {
                let v = u64::from(out[i]) + u64::from(modulus[i]) + carry;
                out[i] = (v & MASK) as u32;
                carry = v >> 29;
            }
        }
        Self(out)
    }
}
impl Neg for F9 {
    type Output = Self;
    #[inline(always)]
    fn neg(self) -> Self {
        Self::ZERO - self
    }
}
impl Mul for F9 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        Self::products([self], [rhs])
    }
}

pub(in crate::kernels) struct F9Scratch {
    scalar: Vec<F9>,
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    paired: Vec<simd::Pair>,
}
impl SmallField for F9 {
    type Scratch = F9Scratch;
    fn scratch(capacity: usize) -> Self::Scratch {
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        {
            F9Scratch {
                scalar: Vec::with_capacity(capacity.min(16)),
                paired: Vec::with_capacity(capacity.div_ceil(2)),
            }
        }
        #[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
        {
            F9Scratch {
                scalar: Vec::with_capacity(capacity),
            }
        }
    }
    fn invert_batch_in(values: &mut [Self], scratch: &mut Self::Scratch) {
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        {
            simd::invert_batch_in(values, &mut scratch.paired, &mut scratch.scalar);
        }
        #[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
        {
            super::batch_inverse_with_prefix(values, &mut scratch.scalar);
        }
    }

    #[inline(always)]
    fn pair_mul(a: Self, b: Self, c: Self, d: Self) -> (Self, Self) {
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        {
            simd::multiply_pair(a, b, c, d)
        }
        #[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
        {
            (a * c, b * d)
        }
    }

    #[cfg(zk_tools_wasm_opt)]
    #[inline(always)]
    fn pair_square(a: Self, b: Self) -> (Self, Self) {
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        {
            simd::square_pair(a, b)
        }
        #[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
        {
            (a.square(), b.square())
        }
    }

    const ZERO: Self = Self([0; 9]);
    const ONE: Self = Self::encode(Fq::ONE);

    #[inline(always)]
    fn dot(a: Self, b: Self, c: Self, d: Self) -> Self {
        Self::products([a, c], [b, d])
    }
    fn inverse(self) -> Option<Self> {
        self.decode().inverse().map(Self::encode)
    }
}
