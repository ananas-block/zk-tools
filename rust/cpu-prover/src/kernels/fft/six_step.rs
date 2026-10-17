use super::Stage;
use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_relations::gr1cs::SynthesisError;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

// Decompose index n = inner + inner_len * outer. The inverse FFT emits
// k = k_outer + outer_len * k_inner, with each row FFT in bit-reversed
// order. The forward FFT uses the swapped decomposition, consuming those
// bit-reversed rows directly. This fuses both FFTs and the coset twist into
// four parallel transpose/compute phases, with no per-stage Rayon barriers.
pub(super) struct SixStep<F> {
    inner_len: usize,
    outer_len: usize,
    inverse_outer: Vec<Stage<F>>,
    forward_outer: Vec<Stage<F>>,
    inverse_inner: Vec<Stage<F>>,
    forward_inner: Vec<Stage<F>>,
    inverse_cross: Vec<F>,
    coset_twist: Vec<F>,
    forward_cross: Vec<F>,
}

fn reverse(index: usize, length: usize) -> usize {
    let bits = length.trailing_zeros();
    if bits == 0 {
        0
    } else {
        index.reverse_bits() >> (usize::BITS - bits)
    }
}

fn powers<F: PrimeField>(root: F, length: usize) -> Vec<F> {
    let mut value = F::one();
    (0..length)
        .map(|_| {
            let result = value;
            value *= root;
            result
        })
        .collect()
}

fn stages<F: PrimeField>(root: F, length: usize, inverse: bool) -> Vec<Stage<F>> {
    let mut result = Vec::new();
    let mut gap = 1;
    while gap < length {
        result.push(Stage {
            gap,
            roots: powers(root.pow([(length / gap / 2) as u64]), gap),
        });
        gap *= 2;
    }
    if inverse {
        result.reverse();
    }
    result
}

impl<F: PrimeField> SixStep<F> {
    pub(super) fn new<D: EvaluationDomain<F>>(
        domain: &D,
        shift: F,
    ) -> Result<Self, SynthesisError> {
        let inner_len = 1 << (domain.size().trailing_zeros() / 2);
        let outer_len = domain.size() / inner_len;
        let root_inner = domain.group_gen().pow([outer_len as u64]);
        let root_outer = domain.group_gen().pow([inner_len as u64]);
        let inv_inner = domain.group_gen_inv().pow([outer_len as u64]);
        let inv_outer = domain.group_gen_inv().pow([inner_len as u64]);
        let inverse_inner = stages(inv_inner, inner_len, true);
        let inverse_outer = stages(inv_outer, outer_len, true);
        let forward_inner = stages(root_inner, inner_len, false);
        let forward_outer = stages(root_outer, outer_len, false);
        let mut inverse_cross = Vec::with_capacity(domain.size());
        for row in 0..inner_len {
            let natural = powers(domain.group_gen_inv().pow([row as u64]), outer_len);
            for column in 0..outer_len {
                inverse_cross.push(
                    *natural
                        .get(reverse(column, outer_len))
                        .ok_or(SynthesisError::AssignmentMissing)?,
                );
            }
        }
        let inner_twist = powers(shift.pow([outer_len as u64]), inner_len);
        let outer_twist = powers(shift, outer_len);
        let mut coset_twist = Vec::with_capacity(domain.size());
        let mut forward_cross = Vec::with_capacity(domain.size());
        for row in 0..outer_len {
            let natural_row = reverse(row, outer_len);
            let factor = domain.size_inv()
                * outer_twist
                    .get(natural_row)
                    .ok_or(SynthesisError::AssignmentMissing)?;
            for column in 0..inner_len {
                coset_twist.push(
                    factor
                        * inner_twist
                            .get(reverse(column, inner_len))
                            .ok_or(SynthesisError::AssignmentMissing)?,
                );
            }
            forward_cross.extend(powers(
                domain.group_gen().pow([natural_row as u64]),
                inner_len,
            ));
        }
        Ok(Self {
            inner_len,
            outer_len,
            inverse_outer,
            forward_outer,
            inverse_inner,
            forward_inner,
            inverse_cross,
            coset_twist,
            forward_cross,
        })
    }

    pub(super) fn transform(&self, values: &mut [F]) {
        let mut buffer = vec![F::zero(); values.len()];
        let first = |((row, output), cross): ((usize, &mut [F]), &[F])| {
            output
                .iter_mut()
                .zip(values.iter().skip(row).step_by(self.inner_len))
                .for_each(|(to, from)| *to = *from);
            for stage in &self.inverse_outer {
                stage.apply_serial(output, true);
            }
            output
                .iter_mut()
                .zip(cross)
                .for_each(|(value, factor)| *value *= factor);
        };
        #[cfg(feature = "parallel")]
        buffer
            .par_chunks_mut(self.outer_len)
            .enumerate()
            .zip(self.inverse_cross.par_chunks(self.outer_len))
            .for_each(first);
        #[cfg(not(feature = "parallel"))]
        buffer
            .chunks_mut(self.outer_len)
            .enumerate()
            .zip(self.inverse_cross.chunks(self.outer_len))
            .for_each(first);
        let middle = |(((row, output), twist), cross): (((usize, &mut [F]), &[F]), &[F])| {
            output
                .iter_mut()
                .zip(buffer.iter().skip(row).step_by(self.outer_len))
                .for_each(|(to, from)| *to = *from);
            for stage in &self.inverse_inner {
                stage.apply_serial(output, true);
            }
            output
                .iter_mut()
                .zip(twist)
                .for_each(|(value, factor)| *value *= factor);
            for stage in &self.forward_inner {
                stage.apply_serial(output, false);
            }
            output
                .iter_mut()
                .zip(cross)
                .for_each(|(value, factor)| *value *= factor);
        };
        #[cfg(feature = "parallel")]
        values
            .par_chunks_mut(self.inner_len)
            .enumerate()
            .zip(self.coset_twist.par_chunks(self.inner_len))
            .zip(self.forward_cross.par_chunks(self.inner_len))
            .for_each(middle);
        #[cfg(not(feature = "parallel"))]
        values
            .chunks_mut(self.inner_len)
            .enumerate()
            .zip(self.coset_twist.chunks(self.inner_len))
            .zip(self.forward_cross.chunks(self.inner_len))
            .for_each(middle);
        let last = |(row, output): (usize, &mut [F])| {
            output
                .iter_mut()
                .zip(values.iter().skip(row).step_by(self.inner_len))
                .for_each(|(to, from)| *to = *from);
            for stage in &self.forward_outer {
                stage.apply_serial(output, false);
            }
        };
        #[cfg(feature = "parallel")]
        buffer
            .par_chunks_mut(self.outer_len)
            .enumerate()
            .for_each(last);
        #[cfg(not(feature = "parallel"))]
        buffer.chunks_mut(self.outer_len).enumerate().for_each(last);
        let transpose = |(row, output): (usize, &mut [F])| {
            output
                .iter_mut()
                .zip(buffer.iter().skip(row).step_by(self.outer_len))
                .for_each(|(to, from)| *to = *from);
        };
        #[cfg(feature = "parallel")]
        values
            .par_chunks_mut(self.inner_len)
            .enumerate()
            .for_each(transpose);
        #[cfg(not(feature = "parallel"))]
        values
            .chunks_mut(self.inner_len)
            .enumerate()
            .for_each(transpose);
    }
}

impl<F: PrimeField> Stage<F> {
    #[inline]
    fn apply_serial(&self, values: &mut [F], inverse: bool) {
        for block in values.chunks_mut(self.gap * 2) {
            let (lo, hi) = block.split_at_mut(self.gap);
            if let (Some((lo, lo_rest)), Some((hi, hi_rest))) =
                (lo.split_first_mut(), hi.split_first_mut())
            {
                let left = *lo;
                *lo += *hi;
                *hi = left - *hi;
                for ((lo, hi), root) in lo_rest
                    .iter_mut()
                    .zip(hi_rest)
                    .zip(self.roots.iter().skip(1))
                {
                    if inverse {
                        let left = *lo;
                        *lo += *hi;
                        *hi = (left - *hi) * root;
                    } else {
                        let right = *hi * root;
                        *hi = *lo - right;
                        *lo += right;
                    }
                }
            }
        }
    }
}
