//! BN254 point formulas and curve-specific GLV operations.
use crate::kernels::field::{base::F9, extension::F92, SmallField};
use ark_bn254::Fr;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, BigInteger256, PrimeField};
mod glv;
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod simd;

pub(in crate::kernels) trait CurveField: SmallField {
    const ENDO: Self;
    const MAX_WINDOW_BITS: usize = 13;
    fn decompose(k: BigInteger256) -> ((bool, BigInteger256), (bool, BigInteger256));
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    fn affine_pair(
        a0: Affine<Self>,
        b0: Affine<Self>,
        i0: Self,
        a1: Affine<Self>,
        b1: Affine<Self>,
        i1: Self,
    ) -> (Affine<Self>, Affine<Self>);
}

impl CurveField for F9 {
    const ENDO: Self =
        Self::encode(<ark_bn254::g1::Config as ark_ec::scalar_mul::glv::GLVConfig>::ENDO_COEFFS[0]);
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
    fn decompose(k: BigInteger256) -> ((bool, BigInteger256), (bool, BigInteger256)) {
        glv::decompose::<ark_bn254::g1::Config>(k)
    }
}
impl CurveField for F92 {
    const ENDO: Self = Self {
        c0: F9::ENDO,
        c1: F9::ZERO,
    };
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
    fn decompose(k: BigInteger256) -> ((bool, BigInteger256), (bool, BigInteger256)) {
        glv::decompose::<ark_bn254::g2::Config>(k)
    }
}
#[derive(Clone, Copy)]
pub(in crate::kernels) struct Affine<F: SmallField> {
    pub(in crate::kernels) x: F,
    pub(in crate::kernels) y: F,
    pub(in crate::kernels) infinity: bool,
}
impl<F: SmallField> Affine<F> {
    pub(in crate::kernels) const ZERO: Self = Self {
        x: F::ZERO,
        y: F::ZERO,
        infinity: true,
    };
    pub(in crate::kernels) fn negate(self) -> Self {
        Self { y: -self.y, ..self }
    }
}
#[derive(Clone, Copy)]
pub(in crate::kernels) struct Projective<F: SmallField> {
    pub(in crate::kernels) x: F,
    pub(in crate::kernels) y: F,
    pub(in crate::kernels) z: F,
}
impl<F: SmallField> Projective<F> {
    pub(in crate::kernels) const ZERO: Self = Self {
        x: F::ONE,
        y: F::ONE,
        z: F::ZERO,
    };
    pub(in crate::kernels) fn is_zero(self) -> bool {
        self.z == F::ZERO
    }
    pub(in crate::kernels) fn from_affine(p: Affine<F>) -> Self {
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
    pub(in crate::kernels) fn double(&mut self) {
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
    pub(in crate::kernels) fn add_mixed(&mut self, other: Affine<F>) {
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
    pub(in crate::kernels) fn add(&mut self, other: Self) {
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

pub(in crate::kernels) fn denominator<F: SmallField>(a: Affine<F>, b: Affine<F>) -> F {
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
pub(in crate::kernels) fn affine_add<F: SmallField>(
    a: Affine<F>,
    b: Affine<F>,
    inverse: F,
) -> Affine<F> {
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
pub(in crate::kernels) fn affine_add_pair<F: CurveField>(
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

pub(in crate::kernels) fn convert_g1(bases: &[ark_bn254::G1Affine]) -> Vec<Affine<F9>> {
    bases
        .iter()
        .map(|p| Affine {
            x: F9::encode(p.x),
            y: F9::encode(p.y),
            infinity: p.is_zero(),
        })
        .collect()
}
pub(in crate::kernels) fn convert_g2(bases: &[ark_bn254::G2Affine]) -> Vec<Affine<F92>> {
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
pub(crate) fn finish_c(
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

pub(in crate::kernels) fn original_g1(r: Projective<F9>) -> ark_bn254::G1Projective {
    ark_bn254::G1Projective::new_unchecked(r.x.decode(), r.y.decode(), r.z.decode())
}
pub(in crate::kernels) fn original_g2(r: Projective<F92>) -> ark_bn254::G2Projective {
    ark_bn254::G2Projective::new_unchecked(r.x.decode(), r.y.decode(), r.z.decode())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../../tests/unit/curve.rs"]
mod tests;
