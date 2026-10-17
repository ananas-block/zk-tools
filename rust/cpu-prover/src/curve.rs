//! Portable BN254 batch-affine MSM.
//! Portable nine-limb BN254 arithmetic retained throughout an MSM.
//!
//! Internal coordinates use nine normalized29-bit limbs and R=2^261.
//! Proving-key coordinates and endomorphisms are prepared once; scalars stay per-proof.
use ark_bn254::{Fq, Fr};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, BigInteger, BigInteger256, Field, PrimeField};
use core::ops::{Add, Mul, Neg, Sub};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::glv;

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[path = "curve_simd.rs"]
mod simd;
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

const MASK: u64 = (1 << 29) - 1;
const Q: [u32; 9] = split(Fq::MODULUS);
const INV: u64 = <ark_bn254::FqConfig as ark_ff::MontConfig<4>>::INV & MASK;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct F9([u32; 9]);

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
    const fn encode(value: Fq) -> Self {
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

    fn decode(self) -> Fq {
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

struct F9Scratch {
    scalar: Vec<F9>,
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    paired: Vec<simd::Pair>,
}
struct F92Scratch {
    norms: Vec<F9>,

    inner: F9Scratch,
}

trait SmallField:
    Copy
    + Eq
    + Send
    + Sync
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
{
    const ZERO: Self;
    const ONE: Self;

    const ENDO: Self;
    const MAX_WINDOW_BITS: usize = 13;

    fn decompose(k: BigInteger256) -> ((bool, BigInteger256), (bool, BigInteger256));
    #[inline(always)]
    fn double(self) -> Self {
        self + self
    }
    #[inline(always)]
    fn square(self) -> Self {
        self * self
    }
    #[inline(always)]
    fn dot(a: Self, b: Self, c: Self, d: Self) -> Self {
        a * b + c * d
    }
    fn inverse(self) -> Option<Self>;

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    fn affine_pair(
        a0: Affine<Self>,
        b0: Affine<Self>,
        i0: Self,
        a1: Affine<Self>,
        b1: Affine<Self>,
        i1: Self,
    ) -> (Affine<Self>, Affine<Self>);
    #[inline(always)]
    fn pair_mul(a: Self, b: Self, c: Self, d: Self) -> (Self, Self) {
        (a * c, b * d)
    }
    #[inline(always)]
    fn pair_square(a: Self, b: Self) -> (Self, Self) {
        Self::pair_mul(a, b, a, b)
    }
    type Scratch;
    fn scratch(capacity: usize) -> Self::Scratch;
    fn invert_batch_in(values: &mut [Self], scratch: &mut Self::Scratch);
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
            batch_inverse_with_prefix(values, &mut scratch.scalar);
        }
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    fn affine_pair(
        a0: Affine<Self>,
        b0: Affine<Self>,
        i0: Self,
        a1: Affine<Self>,
        b1: Affine<Self>,
        i1: Self,
    ) -> (Affine<Self>, Affine<Self>) {
        simd::affine_g1(a0, b0, i0, a1, b1, i1)
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

    const ENDO: Self =
        Self::encode(<ark_bn254::g1::Config as ark_ec::scalar_mul::glv::GLVConfig>::ENDO_COEFFS[0]);

    fn decompose(k: BigInteger256) -> ((bool, BigInteger256), (bool, BigInteger256)) {
        glv::decompose::<ark_bn254::g1::Config>(k)
    }

    #[inline(always)]
    fn dot(a: Self, b: Self, c: Self, d: Self) -> Self {
        Self::products([a, c], [b, d])
    }
    fn inverse(self) -> Option<Self> {
        self.decode().inverse().map(Self::encode)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct F92 {
    c0: F9,
    c1: F9,
}
impl F92 {
    fn encode(value: ark_bn254::Fq2) -> Self {
        Self {
            c0: F9::encode(value.c0),
            c1: F9::encode(value.c1),
        }
    }
    fn decode(self) -> ark_bn254::Fq2 {
        ark_bn254::Fq2::new(self.c0.decode(), self.c1.decode())
    }
}
impl Add for F92 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}
impl Sub for F92 {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
        }
    }
}
impl Neg for F92 {
    type Output = Self;
    #[inline(always)]
    fn neg(self) -> Self {
        Self {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}
impl Mul for F92 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        let (v0, v1) = F9::pair_mul(self.c0, self.c1, rhs.c0, rhs.c1);
        Self {
            c0: v0 - v1,
            c1: (self.c0 + self.c1) * (rhs.c0 + rhs.c1) - v0 - v1,
        }
    }
}
impl SmallField for F92 {
    const MAX_WINDOW_BITS: usize = 10;
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    fn affine_pair(
        a0: Affine<Self>,
        b0: Affine<Self>,
        i0: Self,
        a1: Affine<Self>,
        b1: Affine<Self>,
        i1: Self,
    ) -> (Affine<Self>, Affine<Self>) {
        simd::affine_g2(a0, b0, i0, a1, b1, i1)
    }

    #[inline(always)]
    fn pair_mul(a: Self, b: Self, c: Self, d: Self) -> (Self, Self) {
        let (v00, v01) = F9::pair_mul(a.c0, b.c0, c.c0, d.c0);
        let (v10, v11) = F9::pair_mul(a.c1, b.c1, c.c1, d.c1);
        let (w0, w1) = F9::pair_mul(a.c0 + a.c1, b.c0 + b.c1, c.c0 + c.c1, d.c0 + d.c1);
        (
            Self {
                c0: v00 - v10,
                c1: w0 - v00 - v10,
            },
            Self {
                c0: v01 - v11,
                c1: w1 - v01 - v11,
            },
        )
    }
    #[inline(always)]
    fn pair_square(a: Self, b: Self) -> (Self, Self) {
        let (p0, p1) = F9::pair_mul(a.c0 + a.c1, b.c0 + b.c1, a.c0 - a.c1, b.c0 - b.c1);
        let (q0, q1) = F9::pair_mul(a.c0, b.c0, a.c1, b.c1);
        (
            Self {
                c0: p0,
                c1: q0.double(),
            },
            Self {
                c0: p1,
                c1: q1.double(),
            },
        )
    }

    const ZERO: Self = Self {
        c0: F9::ZERO,
        c1: F9::ZERO,
    };
    const ONE: Self = Self {
        c0: F9::ONE,
        c1: F9::ZERO,
    };

    const ENDO: Self = Self {
        c0: F9::ENDO,
        c1: F9::ZERO,
    };

    fn decompose(k: BigInteger256) -> ((bool, BigInteger256), (bool, BigInteger256)) {
        glv::decompose::<ark_bn254::g2::Config>(k)
    }

    #[inline(always)]
    fn square(self) -> Self {
        let (c0, c1) = F9::pair_mul(self.c0 + self.c1, self.c0, self.c0 - self.c1, self.c1);
        Self {
            c0,
            c1: c1.double(),
        }
    }
    type Scratch = F92Scratch;
    fn scratch(capacity: usize) -> Self::Scratch {
        {
            F92Scratch {
                norms: Vec::with_capacity(capacity),
                inner: F9::scratch(capacity),
            }
        }
    }
    fn invert_batch_in(values: &mut [Self], scratch: &mut Self::Scratch) {
        {
            scratch.norms.clear();
            scratch.norms.extend(values.iter().map(|v| {
                let (a, b) = F9::pair_square(v.c0, v.c1);
                a + b
            }));
            F9::invert_batch_in(&mut scratch.norms, &mut scratch.inner);
            for (value, inverse) in values.iter_mut().zip(scratch.norms.iter().copied()) {
                let (c0, c1) = F9::pair_mul(value.c0, value.c1, inverse, inverse);
                *value = Self { c0, c1: -c1 };
            }
        }
    }
    fn inverse(self) -> Option<Self> {
        let inverse = (self.c0.square() + self.c1.square()).inverse()?;
        Some(Self {
            c0: self.c0 * inverse,
            c1: -self.c1 * inverse,
        })
    }
}

#[derive(Clone, Copy)]
struct Affine<F: SmallField> {
    x: F,
    y: F,
    infinity: bool,
}
impl<F: SmallField> Affine<F> {
    const ZERO: Self = Self {
        x: F::ZERO,
        y: F::ZERO,
        infinity: true,
    };
    fn negate(self) -> Self {
        Self { y: -self.y, ..self }
    }
}
#[derive(Clone, Copy)]
struct Projective<F: SmallField> {
    x: F,
    y: F,
    z: F,
}
impl<F: SmallField> Projective<F> {
    const ZERO: Self = Self {
        x: F::ONE,
        y: F::ONE,
        z: F::ZERO,
    };
    fn is_zero(self) -> bool {
        self.z == F::ZERO
    }
    fn from_affine(p: Affine<F>) -> Self {
        if p.infinity {
            Self::ZERO
        } else {
            Self {
                x: p.x,
                y: p.y,
                z: F::ONE,
            }
        }
    }
    fn double(&mut self) {
        if self.is_zero() {
            return;
        }
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let d = (self.x * b).double().double();
        let e = a.double() + a;
        self.z = (self.z * self.y).double();
        self.x = e.square() - d.double();
        self.y = e * (d - self.x) - c.double().double().double();
    }
    fn add_mixed(&mut self, other: Affine<F>) {
        if other.infinity {
            return;
        }
        if self.is_zero() {
            *self = Self::from_affine(other);
            return;
        }
        let z2 = self.z.square();
        let u2 = other.x * z2;
        let s2 = other.y * self.z * z2;
        if self.x == u2 {
            if self.y == s2 {
                self.double();
            } else {
                *self = Self::ZERO;
            }
            return;
        }
        let h = u2 - self.x;
        let i = h.square().double().double();
        let j = -(h * i);
        let r = (s2 - self.y).double();
        let v = self.x * i;
        self.x = r.square() + j - v.double();
        self.y = F::dot(r, v - self.x, self.y.double(), j);
        self.z = (self.z * h).double();
    }
    fn add(&mut self, other: Self) {
        if self.is_zero() {
            *self = other;
            return;
        }
        if other.is_zero() {
            return;
        }
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x * z2z2;
        let u2 = other.x * z1z1;
        let s1 = self.y * other.z * z2z2;
        let s2 = other.y * self.z * z1z1;
        if u1 == u2 {
            if s1 == s2 {
                self.double();
            } else {
                *self = Self::ZERO;
            }
            return;
        }
        let h = u2 - u1;
        let i = h.double().square();
        let j = -(h * i);
        let r = (s2 - s1).double();
        let v = u1 * i;
        self.x = r.square() + j - v.double();
        self.y = F::dot(r, v - self.x, s1.double(), j);
        self.z = (self.z * other.z).double() * h;
    }
}

fn batch_inverse_with_prefix<F: SmallField>(values: &mut [F], products: &mut Vec<F>) {
    products.clear();
    let mut product = F::ONE;
    for &value in values.iter() {
        products.push(product);
        if value != F::ZERO {
            product = product * value;
        }
    }
    let Some(mut inverse) = product.inverse() else {
        return;
    };
    for (value, prefix) in values.iter_mut().zip(products.iter().copied()).rev() {
        if *value != F::ZERO {
            let next = inverse * (*value);
            *value = inverse * prefix;
            inverse = next;
        }
    }
}
fn denominator<F: SmallField>(a: Affine<F>, b: Affine<F>) -> F {
    if a.infinity || b.infinity {
        F::ZERO
    } else if a.x == b.x {
        if a.y == b.y {
            a.y.double()
        } else {
            F::ZERO
        }
    } else {
        b.x - a.x
    }
}
fn affine_add<F: SmallField>(a: Affine<F>, b: Affine<F>, inverse: F) -> Affine<F> {
    if a.infinity {
        return b;
    }
    if b.infinity {
        return a;
    }
    if inverse == F::ZERO {
        return Affine::ZERO;
    }
    let numerator = if a.x == b.x {
        let x2 = a.x.square();
        x2.double() + x2
    } else {
        b.y - a.y
    };
    let slope = numerator * inverse;
    let x = slope.square() - a.x - b.x;
    Affine {
        x,
        y: slope * (a.x - x) - a.y,
        infinity: false,
    }
}
#[inline]
fn affine_add_pair<F: SmallField>(
    a0: Affine<F>,
    b0: Affine<F>,
    i0: F,
    a1: Affine<F>,
    b1: Affine<F>,
    i1: F,
) -> (Affine<F>, Affine<F>) {
    if a0.infinity
        || b0.infinity
        || a1.infinity
        || b1.infinity
        || i0 == F::ZERO
        || i1 == F::ZERO
        || a0.x == b0.x
        || a1.x == b1.x
    {
        return (affine_add(a0, b0, i0), affine_add(a1, b1, i1));
    }
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        F::affine_pair(a0, b0, i0, a1, b1, i1)
    }
    #[cfg(not(all(target_arch = "wasm32", target_feature = "simd128")))]
    {
        let (s0, s1) = F::pair_mul(b0.y - a0.y, b1.y - a1.y, i0, i1);
        let (ss0, ss1) = F::pair_square(s0, s1);
        let x0 = ss0 - a0.x - b0.x;
        let x1 = ss1 - a1.x - b1.x;
        let (y0, y1) = F::pair_mul(s0, s1, a0.x - x0, a1.x - x1);
        (
            Affine {
                x: x0,
                y: y0 - a0.y,
                infinity: false,
            },
            Affine {
                x: x1,
                y: y1 - a1.y,
                infinity: false,
            },
        )
    }
}

fn sum_buckets<F: SmallField>(
    mut points: Vec<Affine<F>>,
    ranges: &[core::ops::Range<usize>],
) -> Vec<Affine<F>> {
    let max = ranges.iter().map(|r| r.len()).max().unwrap_or(0);
    let mut step = 1;
    let capacity = points.len() / 2;
    let mut pairs = Vec::with_capacity(capacity);
    let mut denominators = Vec::with_capacity(capacity);
    let mut scratch = F::scratch(capacity);
    while step < max {
        pairs.clear();
        denominators.clear();
        for range in ranges {
            for left in range.clone().step_by(2 * step) {
                let right = left + step;
                if right < range.end {
                    pairs.push((left, right));
                    denominators.push(denominator(points[left], points[right]));
                }
            }
        }
        F::invert_batch_in(&mut denominators, &mut scratch);
        let mut work = pairs.iter().copied().zip(denominators.iter().copied());
        while let Some(((l0, r0), i0)) = work.next() {
            if let Some(((l1, r1), i1)) = work.next() {
                let (a, b) =
                    affine_add_pair(points[l0], points[r0], i0, points[l1], points[r1], i1);
                points[l0] = a;
                points[l1] = b;
            } else {
                points[l0] = affine_add(points[l0], points[r0], i0);
            }
        }
        step *= 2;
    }
    ranges
        .iter()
        .map(|r| {
            if r.is_empty() {
                Affine::ZERO
            } else {
                points[r.start]
            }
        })
        .collect()
}

fn window_bits(size: usize) -> usize {
    match size {
        0..=31 => 3,
        32..=127 => 5,
        128..=511 => 6,
        512..=2047 => 8,
        2048..=8191 => 10,
        8192..=32767 => 11,

        _ => 13,
    }
}
fn signed_digits(
    scalar: &BigInteger256,
    c: usize,
    windows: usize,
) -> impl Iterator<Item = i16> + '_ {
    let radix = 1u64 << c;
    let mask = radix - 1;
    let mut carry = 0;
    (0..windows).map(move |window| {
        let start = window * c;
        let limb = start / 64;
        let shift = start % 64;
        let mut raw = scalar.0.get(limb).copied().unwrap_or(0) >> shift;
        if shift != 0 {
            raw |= scalar.0.get(limb + 1).copied().unwrap_or(0) << (64 - shift);
        }
        raw = (raw & mask) + carry;
        if window + 1 == windows {
            raw as i16
        } else {
            carry = (raw + radix / 2) >> c;
            (raw as i64 - (carry * radix) as i64) as i16
        }
    })
}
fn pippenger<F: SmallField>(
    entries: &[(Affine<F>, BigInteger256)],
    c: usize,
    bits: usize,
) -> Projective<F> {
    if entries.is_empty() {
        return Projective::ZERO;
    }
    let windows = (bits + 1).div_ceil(c);
    let mut digits = vec![0i16; entries.len() * windows];
    #[cfg(feature = "parallel")]
    digits
        .par_chunks_mut(windows)
        .zip(entries.par_iter())
        .for_each(|(out, (_, scalar))| {
            out.iter_mut()
                .zip(signed_digits(scalar, c, windows))
                .for_each(|(out, digit)| *out = digit);
        });
    #[cfg(not(feature = "parallel"))]
    digits
        .chunks_mut(windows)
        .zip(entries)
        .for_each(|(out, (_, scalar))| {
            out.iter_mut()
                .zip(signed_digits(scalar, c, windows))
                .for_each(|(out, digit)| *out = digit);
        });
    #[cfg(feature = "parallel")]
    let windows_iter = (0..windows).into_par_iter();
    #[cfg(not(feature = "parallel"))]
    let windows_iter = 0..windows;
    let sums: Vec<_> = windows_iter
        .map(|window| {
            let count = 1 << (c - 1);
            let mut counts = vec![0usize; count];
            for digit in digits.iter().skip(window).step_by(windows) {
                if *digit != 0 {
                    counts[digit.unsigned_abs() as usize - 1] += 1;
                }
            }
            let mut total = 0;
            let ranges: Vec<_> = counts
                .iter()
                .map(|count| {
                    let start = total;
                    total += count;
                    start..total
                })
                .collect();
            let mut cursors: Vec<_> = ranges.iter().map(|r| r.start).collect();
            let mut points = vec![Affine::<F>::ZERO; total];
            for ((base, _), digits) in entries.iter().zip(digits.chunks_exact(windows)) {
                let digit = digits[window];
                if digit == 0 {
                    continue;
                }
                let bucket = digit.unsigned_abs() as usize - 1;
                points[cursors[bucket]] = if digit > 0 { *base } else { base.negate() };
                cursors[bucket] += 1;
            }
            let buckets = sum_buckets(points, &ranges);

            {
                weighted_sum(&buckets)
            }
        })
        .collect();
    let mut result = Projective::ZERO;
    for sum in sums.into_iter().rev() {
        for _ in 0..c {
            result.double();
        }
        result.add(sum);
    }
    result
}

fn weighted_sum<F: SmallField>(buckets: &[Affine<F>]) -> Projective<F> {
    if buckets.len() < 128 {
        let mut running = Projective::ZERO;
        let mut sum = Projective::ZERO;
        for &bucket in buckets.iter().rev() {
            running.add_mixed(bucket);
            sum.add(running);
        }
        return sum;
    }
    let columns = 128;
    let height = buckets.len().div_ceil(columns);
    let mut rows = vec![Affine::ZERO; columns];
    let mut triangles = vec![Affine::ZERO; columns];
    let mut rhs = vec![Affine::ZERO; columns];
    let mut denominators = Vec::with_capacity(columns);
    let mut scratch = F::scratch(columns);
    for offset in (0..height).rev() {
        for (column, target) in rhs.iter_mut().enumerate() {
            *target = buckets
                .get(column * height + offset)
                .copied()
                .unwrap_or(Affine::ZERO);
        }
        batch_add_assign(&mut rows, &rhs, &mut denominators, &mut scratch);
        batch_add_assign(&mut triangles, &rows, &mut denominators, &mut scratch);
    }
    let mut triangle = Projective::ZERO;
    let mut running = Projective::ZERO;
    let mut weighted_rows = Projective::ZERO;
    for (column, (local, row)) in triangles.iter().zip(&rows).enumerate().rev() {
        triangle.add_mixed(*local);
        if column > 0 {
            running.add_mixed(*row);
            weighted_rows.add(running);
        }
    }
    for _ in 0..height.trailing_zeros() {
        weighted_rows.double();
    }
    triangle.add(weighted_rows);
    triangle
}

fn batch_add_assign<F: SmallField>(
    lhs: &mut [Affine<F>],
    rhs: &[Affine<F>],
    denominators: &mut Vec<F>,
    scratch: &mut F::Scratch,
) {
    denominators.clear();
    denominators.extend(lhs.iter().zip(rhs).map(|(a, b)| denominator(*a, *b)));
    F::invert_batch_in(denominators, scratch);
    let mut work = lhs.iter_mut().zip(rhs).zip(denominators);
    while let Some(((a0, b0), i0)) = work.next() {
        if let Some(((a1, b1), i1)) = work.next() {
            let (left, right) = affine_add_pair(*a0, *b0, *i0, *a1, *b1, *i1);
            *a0 = left;
            *a1 = right;
        } else {
            *a0 = affine_add(*a0, *b0, *i0);
        }
    }
}

fn msm_internal<F: SmallField>(
    bases: &[Affine<F>],
    scalars: &[BigInteger256],
    endomorphism_x: Option<&[F]>,
) -> Projective<F> {
    let mut endomorphism_x = endomorphism_x.map(|values| values.iter());
    let mut units = Projective::ZERO;
    let mut groups: [Vec<(Affine<F>, BigInteger256)>; 5] = Default::default();
    for (&base, &scalar) in bases.iter().zip(scalars) {
        let cached_x = endomorphism_x
            .as_mut()
            .and_then(|values| values.next())
            .copied();
        if scalar.is_zero() || base.infinity {
            continue;
        }
        let mut magnitude = scalar;
        let mut base = base;
        if scalar.num_bits() > 64 && scalar <= Fr::MODULUS {
            let mut negative = Fr::MODULUS;
            negative.sub_with_borrow(&scalar);
            if negative.num_bits() <= 64 {
                magnitude = negative;
                base = base.negate();
            }
        }
        match magnitude.num_bits() {
            0 => (),
            1 => units.add_mixed(base),
            bits => {
                let group = match bits {
                    2..=8 => 0,
                    9..=16 => 1,
                    17..=32 => 2,
                    33..=64 => 3,
                    _ => 4,
                };

                if group == 4 {
                    let ((s1, k1), (s2, k2)) = F::decompose(magnitude);
                    groups[group].push((if s1 { base } else { base.negate() }, k1));

                    let x = cached_x.unwrap_or_else(|| base.x * F::ENDO);

                    let endo = Affine { x, ..base };
                    groups[group].push((if s2 { endo } else { endo.negate() }, k2));
                } else {
                    groups[group].push((base, magnitude));
                }
            }
        }
    }
    #[cfg(feature = "parallel")]
    let sums = groups.into_par_iter();
    #[cfg(not(feature = "parallel"))]
    let sums = groups.into_iter();
    let sums: Vec<_> = sums
        .map(|entries| {
            let bits = entries.iter().map(|(_, s)| s.num_bits()).max().unwrap_or(0) as usize;
            pippenger(
                &entries,
                window_bits(entries.len()).min(F::MAX_WINDOW_BITS),
                bits,
            )
        })
        .collect();
    for sum in sums {
        units.add(sum);
    }
    units
}

fn convert_g1(bases: &[ark_bn254::G1Affine]) -> Vec<Affine<F9>> {
    bases
        .iter()
        .map(|p| Affine {
            x: F9::encode(p.x),
            y: F9::encode(p.y),
            infinity: p.is_zero(),
        })
        .collect()
}
fn convert_g2(bases: &[ark_bn254::G2Affine]) -> Vec<Affine<F92>> {
    bases
        .iter()
        .map(|p| Affine {
            x: F92::encode(p.x),
            y: F92::encode(p.y),
            infinity: p.is_zero(),
        })
        .collect()
}
/// Joint GLV ladder for the two variable G1 terms in Groth16's final C.
/// Signed components share one ~130-bit doubling chain. The subset table is
/// local to this proof: no scalar or witness-derived point is retained.
#[cfg(any(test, all(target_arch = "wasm32", target_feature = "simd128")))]
pub(super) fn finish_c(
    a: ark_bn254::G1Projective,
    b: ark_bn254::G1Projective,
    r: Fr,
    s: Fr,
    l: ark_bn254::G1Projective,
    h: ark_bn254::G1Projective,
) -> ark_bn254::G1Projective {
    let convert = |p: ark_bn254::G1Projective| Projective {
        x: F9::encode(p.x),
        y: F9::encode(p.y),
        z: F9::encode(p.z),
    };
    let mut bases = [Projective::<F9>::ZERO; 4];
    let mut components = [BigInteger256::default(); 4];
    for (i, (point, scalar)) in [(a, s), (b, r)].into_iter().enumerate() {
        let p = convert(point);
        let ((positive0, k0), (positive1, k1)) = F9::decompose(scalar.into_bigint());
        bases[2 * i] = Projective {
            y: if positive0 { p.y } else { -p.y },
            ..p
        };
        bases[2 * i + 1] = Projective {
            x: p.x * F9::ENDO,
            y: if positive1 { p.y } else { -p.y },
            z: p.z,
        };
        components[2 * i] = k0;
        components[2 * i + 1] = k1;
    }
    let mut table = [Projective::<F9>::ZERO; 16];
    for mask in 1usize..16 {
        let bit = mask.trailing_zeros() as usize;
        table[mask] = table[mask & (mask - 1)];
        table[mask].add(bases[bit]);
    }
    let bits = components
        .iter()
        .map(BigInteger::num_bits)
        .max()
        .unwrap_or(0);
    let mut sum = Projective::<F9>::ZERO;
    for bit in (0..bits).rev() {
        sum.double();
        let mut mask = 0;
        for (i, scalar) in components.iter().enumerate() {
            mask |= usize::from(scalar.get_bit(bit as usize)) << i;
        }
        if mask != 0 {
            sum.add(table[mask]);
        }
    }
    sum.add(convert(l));
    sum.add(convert(h));
    original_g1(sum)
}

fn original_g1(r: Projective<F9>) -> ark_bn254::G1Projective {
    ark_bn254::G1Projective::new_unchecked(r.x.decode(), r.y.decode(), r.z.decode())
}
fn original_g2(r: Projective<F92>) -> ark_bn254::G2Projective {
    ark_bn254::G2Projective::new_unchecked(r.x.decode(), r.y.decode(), r.z.decode())
}

pub(super) struct PreparedG1 {
    bases: Vec<Affine<F9>>,

    endo_x: Vec<F9>,
}

impl PreparedG1 {
    fn new(bases: &[ark_bn254::G1Affine]) -> Self {
        let bases = convert_g1(bases);

        let endo_x = bases.iter().map(|p| p.x * F9::ENDO).collect();
        Self { bases, endo_x }
    }
    pub(super) fn msm(&self, scalars: &[BigInteger256]) -> ark_bn254::G1Projective {
        original_g1(msm_internal(&self.bases, scalars, Some(&self.endo_x)))
    }
    pub(super) fn query(&self, scalars: &[BigInteger256]) -> Option<ark_bn254::G1Projective> {
        let bases = self.bases.get(1..)?;

        let endo = self.endo_x.get(1..)?;
        Some(original_g1(msm_internal(bases, scalars, Some(endo))))
    }
}

pub(super) struct PreparedG2 {
    bases: Vec<Affine<F92>>,

    endo_x: Vec<F92>,
}

impl PreparedG2 {
    fn new(bases: &[ark_bn254::G2Affine]) -> Self {
        let bases = convert_g2(bases);

        let endo_x = bases.iter().map(|p| p.x * F92::ENDO).collect();
        Self { bases, endo_x }
    }
    pub(super) fn query(&self, scalars: &[BigInteger256]) -> Option<ark_bn254::G2Projective> {
        let bases = self.bases.get(1..)?;

        let endo = self.endo_x.get(1..)?;
        Some(original_g2(msm_internal(bases, scalars, Some(endo))))
    }
}
/// Read-only coordinates derived solely from one immutable proving key.
/// Witness values and randomizers are never cached.

pub(super) struct PreparedKey {
    pub(super) h: PreparedG1,
    pub(super) l: PreparedG1,
    pub(super) a: PreparedG1,
    pub(super) b1: PreparedG1,
    pub(super) b2: PreparedG2,
}

impl PreparedKey {
    pub(super) fn new(
        h: &[ark_bn254::G1Affine],
        l: &[ark_bn254::G1Affine],
        a: &[ark_bn254::G1Affine],
        b1: &[ark_bn254::G1Affine],
        b2: &[ark_bn254::G2Affine],
    ) -> Self {
        Self {
            h: PreparedG1::new(h),
            l: PreparedG1::new(l),
            a: PreparedG1::new(a),
            b1: PreparedG1::new(b1),
            b2: PreparedG2::new(b2),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/unit/curve.rs"]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/unit/curve_finish.rs"]
mod finish_joint_tests;
