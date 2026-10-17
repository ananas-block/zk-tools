//! Prepared GLV/Pippenger MSM with batch-affine bucket accumulation.
use crate::kernels::{
    curve::{
        affine_add, affine_add_pair, convert_g1, convert_g2, denominator, original_g1, original_g2,
        Affine, CurveField, Projective,
    },
    field::{base::F9, extension::F92},
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, BigInteger256, PrimeField};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

fn sum_buckets<F: CurveField>(
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
fn pippenger<F: CurveField>(
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

fn weighted_sum<F: CurveField>(buckets: &[Affine<F>]) -> Projective<F> {
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

fn batch_add_assign<F: CurveField>(
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

fn msm_internal<F: CurveField>(
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

pub(crate) struct PreparedG1 {
    bases: Vec<Affine<F9>>,

    endo_x: Vec<F9>,
}

impl PreparedG1 {
    fn new(bases: &[ark_bn254::G1Affine]) -> Self {
        let bases = convert_g1(bases);

        let endo_x = bases.iter().map(|p| p.x * F9::ENDO).collect();
        Self { bases, endo_x }
    }
    pub(crate) fn msm(&self, scalars: &[BigInteger256]) -> ark_bn254::G1Projective {
        original_g1(msm_internal(&self.bases, scalars, Some(&self.endo_x)))
    }
    pub(crate) fn query(&self, scalars: &[BigInteger256]) -> Option<ark_bn254::G1Projective> {
        let bases = self.bases.get(1..)?;

        let endo = self.endo_x.get(1..)?;
        Some(original_g1(msm_internal(bases, scalars, Some(endo))))
    }
}

pub(crate) struct PreparedG2 {
    bases: Vec<Affine<F92>>,

    endo_x: Vec<F92>,
}

impl PreparedG2 {
    fn new(bases: &[ark_bn254::G2Affine]) -> Self {
        let bases = convert_g2(bases);

        let endo_x = bases.iter().map(|p| p.x * F92::ENDO).collect();
        Self { bases, endo_x }
    }
    pub(crate) fn query(&self, scalars: &[BigInteger256]) -> Option<ark_bn254::G2Projective> {
        let bases = self.bases.get(1..)?;

        let endo = self.endo_x.get(1..)?;
        Some(original_g2(msm_internal(bases, scalars, Some(endo))))
    }
}
/// Read-only coordinates derived solely from one immutable proving key.
/// Witness values and randomizers are never cached.

pub(crate) struct PreparedKey {
    pub(crate) h: PreparedG1,
    pub(crate) l: PreparedG1,
    pub(crate) a: PreparedG1,
    pub(crate) b1: PreparedG1,
    pub(crate) b2: PreparedG2,
}

impl PreparedKey {
    pub(crate) fn new(
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
#[path = "../../../tests/unit/msm.rs"]
mod tests;
