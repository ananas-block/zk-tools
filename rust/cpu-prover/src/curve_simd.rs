//! Portable SIMD adaptation of delayed-carry Montgomery arithmetic; see THIRD_PARTY_NOTICES.
//! Two independent normalized29-bit field values in standard WASM SIMD128.
//! Products use i64x2.extmul_low_i32x4_u, mapping to native NEON UMULL.
use super::{Affine, SmallField, F9, F92, MASK, Q};
use core::{
    arch::wasm32::*,
    ops::{Add, Mul, Sub},
};

// Keep this tiny operation opaque to LLVM so loop invariant motion cannot
// hoist its input extensions and replace UMULL with emulated64-bit multiply.
// The helper remains within the WASM module. Its C ABI returns v128 directly;
// Rust ABI would introduce a result pointer. Browser inlining can fuse it.

#[inline(never)]
#[allow(improper_ctypes_definitions)]
extern "C" fn extmul(a: v128, b: v128) -> v128 {
    u64x2_extmul_low_u32x4(a, b)
}

#[derive(Clone, Copy)]
pub(super) struct Pair([v128; 9]);
impl Pair {
    #[inline(always)]
    fn pack(a: F9, b: F9) -> Self {
        Self(core::array::from_fn(|j| {
            u32x4(a.0[j], b.0[j], a.0[j], b.0[j])
        }))
    }
    #[inline(always)]
    fn unpack(self) -> (F9, F9) {
        (
            F9(self.0.map(|v| u32x4_extract_lane::<0>(v))),
            F9(self.0.map(|v| u32x4_extract_lane::<1>(v))),
        )
    }
    #[inline(always)]
    fn reduce_to(self, limit: [u32; 9]) -> Self {
        if u32x4_all_true(u32x4_lt(self.0[8], u32x4_splat(limit[8]))) {
            return self;
        }
        let mut greater = i32x4_splat(0);
        let mut equal = i32x4_splat(-1);
        for j in (0..9).rev() {
            let q = u32x4_splat(limit[j]);
            greater = v128_or(greater, v128_and(equal, u32x4_gt(self.0[j], q)));
            equal = v128_and(equal, i32x4_eq(self.0[j], q));
        }
        let subtract = v128_or(greater, equal);
        let mut borrow = i32x4_splat(0);
        let mut out = [i32x4_splat(0); 9];
        for j in 0..9 {
            let v = i32x4_add(
                i32x4_sub(self.0[j], v128_and(u32x4_splat(limit[j]), subtract)),
                borrow,
            );
            out[j] = v128_and(v, u32x4_splat(MASK as u32));
            borrow = i32x4_shr(v, 29);
        }
        Self(out)
    }
}
impl Add for Pair {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut carry = i32x4_splat(0);
        let mut out = [carry; 9];
        for j in 0..9 {
            let v = i32x4_add(i32x4_add(self.0[j], rhs.0[j]), carry);
            out[j] = v128_and(v, u32x4_splat(MASK as u32));
            carry = u32x4_shr(v, 29);
        }

        {
            Self(out).reduce_to(Q)
        }
    }
}
impl Sub for Pair {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        let mut borrow = i32x4_splat(0);
        let mut out = [borrow; 9];
        for j in 0..9 {
            let v = i32x4_add(i32x4_sub(self.0[j], rhs.0[j]), borrow);
            out[j] = v128_and(v, u32x4_splat(MASK as u32));
            borrow = i32x4_shr(v, 29);
        }
        if i32x4_all_true(i32x4_eq(borrow, i32x4_splat(0))) {
            return Self(out);
        }

        let modulus = Q;
        let mut carry = i32x4_splat(0);
        for j in 0..9 {
            let v = i32x4_add(
                i32x4_add(out[j], v128_and(u32x4_splat(modulus[j]), borrow)),
                carry,
            );
            out[j] = v128_and(v, u32x4_splat(MASK as u32));
            carry = u32x4_shr(v, 29);
        }
        Self(out)
    }
}
impl Mul for Pair {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        montgomery_pair(self, rhs)
    }
}
#[cfg_attr(zk_tools_wasm_opt, inline(always))]
#[cfg_attr(not(zk_tools_wasm_opt), inline(never))]
fn montgomery_pair(lhs: Pair, rhs: Pair) -> Pair {
    let zero = i64x2_splat(0);
    let mut t = [zero; 9];
    let mask = i64x2_splat(MASK as i64);
    for i in 0..9 {
        let a = lhs.0[i];
        let lo = i64x2_add(t[0], extmul(a, rhs.0[0]));
        let packed = u32x4_shuffle::<0, 2, 0, 2>(lo, lo);
        let m = v128_and(
            u32x4_mul(packed, u32x4_splat(super::INV as u32)),
            u32x4_splat(MASK as u32),
        );
        let carry = u64x2_shr(i64x2_add(lo, extmul(m, u32x4_splat(Q[0]))), 29);
        for j in 1..9 {
            let mut v = i64x2_add(t[j], extmul(m, u32x4_splat(Q[j])));
            v = i64x2_add(v, extmul(a, rhs.0[j]));
            if j == 1 {
                v = i64x2_add(v, carry);
            }
            t[j - 1] = v;
        }
        t[8] = zero;
    }
    let mut out = [zero; 9];
    let mut carry = zero;
    for j in 0..9 {
        let v = i64x2_add(t[j], carry);
        let digits = v128_and(v, mask);
        out[j] = u32x4_shuffle::<0, 2, 0, 2>(digits, digits);
        carry = u64x2_shr(v, 29);
    }

    {
        Pair(out).reduce_to(Q)
    }
}

// Enabled only with the postlink optimizer: early LLVM inlining removes
// argument/result buffers, then Binaryen fuses the opaque extmul helpers.
// Symmetric Comba product:45 distinct operand products instead of81.
// Normalized29-bit inputs give at most9 operand and9 modulus products in
// each delayed column, below18*2^58 plus carries and therefore below2^63.
#[cfg(zk_tools_wasm_opt)]
#[inline(never)]
fn montgomery_square(lhs: Pair) -> Pair {
    let zero = i64x2_splat(0);
    let mut t = [zero; 18];
    // Literal indices let LLVM scalarize the delayed columns into locals.
    macro_rules! diagonal {
        ($i:literal) => {
            t[2 * $i] = i64x2_add(t[2 * $i], extmul(lhs.0[$i], lhs.0[$i]));
        };
    }
    macro_rules! cross {
        ($i:literal, $j:literal) => {{
            let product = extmul(lhs.0[$i], lhs.0[$j]);
            t[$i + $j] = i64x2_add(t[$i + $j], i64x2_add(product, product));
        }};
    }
    diagonal!(0);
    cross!(0, 1);
    cross!(0, 2);
    cross!(0, 3);
    cross!(0, 4);
    cross!(0, 5);
    cross!(0, 6);
    cross!(0, 7);
    cross!(0, 8);
    diagonal!(1);
    cross!(1, 2);
    cross!(1, 3);
    cross!(1, 4);
    cross!(1, 5);
    cross!(1, 6);
    cross!(1, 7);
    cross!(1, 8);
    diagonal!(2);
    cross!(2, 3);
    cross!(2, 4);
    cross!(2, 5);
    cross!(2, 6);
    cross!(2, 7);
    cross!(2, 8);
    diagonal!(3);
    cross!(3, 4);
    cross!(3, 5);
    cross!(3, 6);
    cross!(3, 7);
    cross!(3, 8);
    diagonal!(4);
    cross!(4, 5);
    cross!(4, 6);
    cross!(4, 7);
    cross!(4, 8);
    diagonal!(5);
    cross!(5, 6);
    cross!(5, 7);
    cross!(5, 8);
    diagonal!(6);
    cross!(6, 7);
    cross!(6, 8);
    diagonal!(7);
    cross!(7, 8);
    diagonal!(8);
    macro_rules! modulus_product {
        ($i:literal, $j:literal, $m:ident) => {
            t[$i + $j] = i64x2_add(t[$i + $j], extmul($m, u32x4_splat(Q[$j])));
        };
    }
    macro_rules! round {
        ($i:literal) => {{
            let packed = u32x4_shuffle::<0, 2, 0, 2>(t[$i], t[$i]);
            let m = v128_and(
                u32x4_mul(packed, u32x4_splat(super::INV as u32)),
                u32x4_splat(MASK as u32),
            );
            let carry = u64x2_shr(i64x2_add(t[$i], extmul(m, u32x4_splat(Q[0]))), 29);
            t[$i + 1] = i64x2_add(t[$i + 1], carry);
            modulus_product!($i, 1, m);
            modulus_product!($i, 2, m);
            modulus_product!($i, 3, m);
            modulus_product!($i, 4, m);
            modulus_product!($i, 5, m);
            modulus_product!($i, 6, m);
            modulus_product!($i, 7, m);
            modulus_product!($i, 8, m);
        }};
    }
    round!(0);
    round!(1);
    round!(2);
    round!(3);
    round!(4);
    round!(5);
    round!(6);
    round!(7);
    round!(8);
    let mut out = [zero; 9];
    let mut carry = zero;
    let mask = i64x2_splat(MASK as i64);
    macro_rules! normalize {
        ($j:literal) => {{
            let value = i64x2_add(t[9 + $j], carry);
            let digits = v128_and(value, mask);
            out[$j] = u32x4_shuffle::<0, 2, 0, 2>(digits, digits);
            carry = u64x2_shr(value, 29);
        }};
    }
    normalize!(0);
    normalize!(1);
    normalize!(2);
    normalize!(3);
    normalize!(4);
    normalize!(5);
    normalize!(6);
    normalize!(7);
    let value = i64x2_add(t[17], carry);
    let digits = v128_and(value, mask);
    out[8] = u32x4_shuffle::<0, 2, 0, 2>(digits, digits);
    Pair(out).reduce_to(Q)
}

trait Packed: Copy + Add<Output = Self> + Sub<Output = Self> + Mul<Output = Self> {
    #[inline(always)]
    fn square(self) -> Self {
        self * self
    }
}
impl Packed for Pair {
    #[cfg(zk_tools_wasm_opt)]
    #[inline(always)]
    fn square(self) -> Self {
        montgomery_square(self)
    }
}
#[derive(Clone, Copy)]
struct Complex {
    c0: Pair,
    c1: Pair,
}
impl Complex {
    #[inline(always)]
    fn pack(a: F92, b: F92) -> Self {
        Self {
            c0: Pair::pack(a.c0, b.c0),
            c1: Pair::pack(a.c1, b.c1),
        }
    }
    #[inline(always)]
    fn unpack(self) -> (F92, F92) {
        let (a, b) = self.c0.unpack();
        let (c, d) = self.c1.unpack();
        (F92 { c0: a, c1: c }, F92 { c0: b, c1: d })
    }
}
impl Add for Complex {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
        }
    }
}
impl Sub for Complex {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
        }
    }
}
impl Mul for Complex {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        let v0 = self.c0 * rhs.c0;
        let v1 = self.c1 * rhs.c1;
        Self {
            c0: v0 - v1,
            c1: (self.c0 + self.c1) * (rhs.c0 + rhs.c1) - v0 - v1,
        }
    }
}
impl Packed for Complex {
    #[inline(always)]
    fn square(self) -> Self {
        let ab = self.c0 * self.c1;
        Self {
            c0: (self.c0 + self.c1) * (self.c0 - self.c1),
            c1: ab + ab,
        }
    }
}
#[inline(always)]
fn affine_formula<P: Packed>(ax: P, ay: P, bx: P, by: P, inverse: P) -> (P, P) {
    let slope = (by - ay) * inverse;
    let x = slope.square() - ax - bx;
    let y = slope * (ax - x) - ay;
    (x, y)
}
pub(super) fn affine_g1(
    a0: Affine<F9>,
    b0: Affine<F9>,
    i0: F9,
    a1: Affine<F9>,
    b1: Affine<F9>,
    i1: F9,
) -> (Affine<F9>, Affine<F9>) {
    let (x, y) = affine_formula(
        Pair::pack(a0.x, a1.x),
        Pair::pack(a0.y, a1.y),
        Pair::pack(b0.x, b1.x),
        Pair::pack(b0.y, b1.y),
        Pair::pack(i0, i1),
    );
    let (x0, x1) = x.unpack();
    let (y0, y1) = y.unpack();
    (
        Affine {
            x: x0,
            y: y0,
            infinity: false,
        },
        Affine {
            x: x1,
            y: y1,
            infinity: false,
        },
    )
}
pub(super) fn affine_g2(
    a0: Affine<F92>,
    b0: Affine<F92>,
    i0: F92,
    a1: Affine<F92>,
    b1: Affine<F92>,
    i1: F92,
) -> (Affine<F92>, Affine<F92>) {
    let (x, y) = affine_formula(
        Complex::pack(a0.x, a1.x),
        Complex::pack(a0.y, a1.y),
        Complex::pack(b0.x, b1.x),
        Complex::pack(b0.y, b1.y),
        Complex::pack(i0, i1),
    );
    let (x0, x1) = x.unpack();
    let (y0, y1) = y.unpack();
    (
        Affine {
            x: x0,
            y: y0,
            infinity: false,
        },
        Affine {
            x: x1,
            y: y1,
            infinity: false,
        },
    )
}
#[inline(always)]
pub(super) fn multiply_pair(a: F9, b: F9, c: F9, d: F9) -> (F9, F9) {
    (Pair::pack(a, b) * Pair::pack(c, d)).unpack()
}

#[cfg(zk_tools_wasm_opt)]
#[inline(always)]
pub(super) fn square_pair(a: F9, b: F9) -> (F9, F9) {
    Pair::pack(a, b).square().unpack()
}

// Two independent Montgomery-trick chains share vector arithmetic through
// their complete prefix/suffix passes. Two scalar inversions are amortized
// over the whole batch, and zero entries remain zero.

#[cfg(feature = "test-support")]
pub(super) fn invert_batch(values: &mut [F9]) {
    invert_batch_in(
        values,
        &mut Vec::with_capacity(values.len().div_ceil(2)),
        &mut Vec::new(),
    );
}

pub(super) fn invert_batch_in(
    values: &mut [F9],
    prefixes: &mut Vec<Pair>,
    scalar_prefix: &mut Vec<F9>,
) {
    prefixes.clear();
    if values.len() < 16 {
        super::batch_inverse_with_prefix(values, scalar_prefix);
        return;
    }
    let half = values.len().div_ceil(2);
    let mut product = Pair::pack(F9::ONE, F9::ONE);
    for i in 0..half {
        let a = values[i];
        let b = values.get(i + half).copied().unwrap_or(F9::ZERO);
        let za = a == F9::ZERO;
        let zb = b == F9::ZERO;
        prefixes.push(product);
        let factor = Pair::pack(if za { F9::ONE } else { a }, if zb { F9::ONE } else { b });
        if !(za && zb) {
            product = product * factor;
        }
    }
    let (a, b) = product.unpack();
    let (Some(a), Some(b)) = (a.inverse(), b.inverse()) else {
        super::batch_inverse_with_prefix(values, scalar_prefix);
        return;
    };
    let mut inverse = Pair::pack(a, b);
    for i in (0..half).rev() {
        let original_a = values[i];
        let original_b = values.get(i + half).copied().unwrap_or(F9::ZERO);
        let za = original_a == F9::ZERO;
        let zb = original_b == F9::ZERO;
        if za && zb {
            values[i] = F9::ZERO;
            if let Some(v) = values.get_mut(i + half) {
                *v = F9::ZERO;
            }
            continue;
        }
        let result = inverse * prefixes[i];
        // Original entries at this pair have not yet been overwritten.
        // Repacking saves a second144-byte-per-pair scratch allocation.
        inverse = inverse
            * Pair::pack(
                if za { F9::ONE } else { original_a },
                if zb { F9::ONE } else { original_b },
            );
        let (a, b) = result.unpack();
        values[i] = if za { F9::ZERO } else { a };
        if let Some(v) = values.get_mut(i + half) {
            *v = if zb { F9::ZERO } else { b };
        }
    }
}

// This runs the actual vector code in a WASM browser, separately from proof
// timing. Native fallback tests alone do not exercise SIMD intrinsics.
#[cfg(feature = "test-support")]
pub(super) fn self_test(mut seed: u32, count: u32) -> bool {
    use ark_ff::{AdditiveGroup, Field, PrimeField};
    for i in 0..count {
        let mut next = || {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_exact_mut(4) {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                chunk.copy_from_slice(&seed.to_le_bytes());
            }
            ark_bn254::Fq::from_le_bytes_mod_order(&bytes)
        };
        let mut a = if i % 8 == 0 {
            ark_bn254::Fq::ONE
        } else {
            next()
        };
        let b = if i % 7 == 0 {
            -ark_bn254::Fq::ONE
        } else {
            next()
        };
        let c = if i % 5 == 0 {
            ark_bn254::Fq::ZERO
        } else {
            next()
        };
        let d = next();
        let fa = match i % 16 {
            2 => {
                let mut raw = Q;
                raw[0] -= 1;
                let v = F9(raw);
                a = v.decode();
                v
            }
            3 => {
                let mut raw = [0; 9];
                for limb in raw.iter_mut().take(6) {
                    *limb = MASK as u32;
                }
                raw[6] = (1 << 18) - 1;
                let v = F9(raw);
                a = v.decode();
                v
            }
            _ => F9::encode(a),
        };
        let p = Pair::pack(fa, F9::encode(b));
        let q = Pair::pack(F9::encode(c), F9::encode(d));
        let (x, y) = p.square().unpack();
        if x.decode() != a.square() || y.decode() != b.square() {
            return false;
        }
        let (x, y) = F9::pair_square(fa, F9::encode(b));
        if x.decode() != a.square() || y.decode() != b.square() {
            return false;
        }
        let (x, y) = (p * q).unpack();
        if x.decode() != a * c || y.decode() != b * d {
            return false;
        }
        let (x, y) = (p + q).unpack();
        if x.decode() != a + c || y.decode() != b + d {
            return false;
        }
        let (x, y) = (p - q).unpack();
        if x.decode() != a - c || y.decode() != b - d {
            return false;
        }
        if i % 64 == 0 {
            let ca = F92 {
                c0: F9::encode(a),
                c1: F9::encode(b),
            };
            let cb = F92 {
                c0: F9::encode(c),
                c1: F9::encode(d),
            };
            let cc = F92 {
                c0: F9::encode(b),
                c1: F9::encode(a),
            };
            let p = Complex::pack(ca, cb);
            let q = Complex::pack(cb, cc);
            let (x, y) = (p * q).unpack();
            if x.decode() != ca.decode() * cb.decode() || y.decode() != cb.decode() * cc.decode() {
                return false;
            }
            let (x, y) = p.square().unpack();
            if x.decode() != ca.decode().square() || y.decode() != cb.decode().square() {
                return false;
            }
        }
    }

    for n in [0usize, 1, 2, 3, 15, 16, 17, 31, 128, 257] {
        let mut values: Vec<_> = (0..n)
            .map(|i| {
                if i % 7 == 0 {
                    F9::ZERO
                } else {
                    F9::encode(ark_bn254::Fq::from((i as u64 + 1) * 0x1deaf))
                }
            })
            .collect();
        let expected: Vec<_> = values
            .iter()
            .map(|v| v.decode().inverse().unwrap_or(ark_bn254::Fq::ZERO))
            .collect();
        invert_batch(&mut values);
        if values.into_iter().map(F9::decode).collect::<Vec<_>>() != expected {
            return false;
        }
    }
    true
}
