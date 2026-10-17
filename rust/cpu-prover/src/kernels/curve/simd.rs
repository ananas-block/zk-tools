use super::Affine;
use crate::kernels::field::{
    base::F9,
    extension::F92,
    simd::{Complex, Packed, Pair},
};

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
