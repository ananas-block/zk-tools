//! Quadratic extension arithmetic over the portable BN254 base field.
use super::{
    base::{F9Scratch, F9},
    SmallField,
};
use core::ops::{Add, Mul, Neg, Sub};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::kernels) struct F92 {
    pub(in crate::kernels) c0: F9,
    pub(in crate::kernels) c1: F9,
}
impl F92 {
    pub(in crate::kernels) fn encode(value: ark_bn254::Fq2) -> Self {
        Self {
            c0: F9::encode(value.c0),
            c1: F9::encode(value.c1),
        }
    }
    pub(in crate::kernels) fn decode(self) -> ark_bn254::Fq2 {
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
pub(in crate::kernels) struct F92Scratch {
    norms: Vec<F9>,

    inner: F9Scratch,
}

impl SmallField for F92 {
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
