use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_relations::gr1cs::SynthesisError;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

mod six_step;

struct Stage<F> {
    gap: usize,
    roots: Vec<F>,
}
pub(super) struct Plan<F> {
    six_step: Option<six_step::SixStep<F>>,
    inverse: Vec<Stage<F>>,
    forward: Vec<Stage<F>>,
    twist: Vec<F>,
}

pub(super) fn plan<F: PrimeField, D: EvaluationDomain<F>>(
    domain: &D,
    shift: F,
) -> Result<Arc<Plan<F>>, SynthesisError> {
    type Cache = HashMap<(TypeId, usize, Vec<u64>, Vec<u64>), Arc<dyn Any + Send + Sync>>;
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (
        TypeId::of::<F>(),
        domain.size(),
        domain.group_gen().into_bigint().as_ref().to_vec(),
        shift.into_bigint().as_ref().to_vec(),
    );
    if let Some(value) = cache
        .lock()
        .map_err(|_| SynthesisError::AssignmentMissing)?
        .get(&key)
    {
        if let Ok(value) = Arc::clone(value).downcast::<Plan<F>>() {
            return Ok(value);
        }
    }
    if !domain.size().is_power_of_two() {
        return Err(SynthesisError::PolynomialDegreeTooLarge);
    }
    if domain.size() >= 256 {
        let result = Arc::new(Plan {
            inverse: Vec::new(),
            forward: Vec::new(),
            twist: Vec::new(),
            six_step: Some(six_step::SixStep::new(domain, shift)?),
        });
        cache
            .lock()
            .map_err(|_| SynthesisError::AssignmentMissing)?
            .insert(key, result.clone());
        return Ok(result);
    }
    let mut forward = Vec::new();
    let mut inverse = Vec::new();
    let mut gap = 1;
    while gap < domain.size() {
        let power = (domain.size() / gap / 2) as u64;
        let mut roots = vec![F::one(); gap];
        D::distribute_powers(&mut roots, domain.group_gen().pow([power]));
        forward.push(Stage { gap, roots });
        let mut roots = vec![F::one(); gap];
        D::distribute_powers(&mut roots, domain.group_gen_inv().pow([power]));
        inverse.push(Stage { gap, roots });
        gap *= 2;
    }
    inverse.reverse();
    let mut powers = vec![F::one(); domain.size()];
    D::distribute_powers_and_mul_by_const(&mut powers, shift, domain.size_inv());
    let bits = domain.size().trailing_zeros();
    let twist = (0..domain.size())
        .map(|i| {
            let index = if bits == 0 {
                0
            } else {
                i.reverse_bits() >> (usize::BITS - bits)
            };
            powers
                .get(index)
                .copied()
                .ok_or(SynthesisError::AssignmentMissing)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let result = Arc::new(Plan {
        six_step: None,
        inverse,
        forward,
        twist,
    });
    cache
        .lock()
        .map_err(|_| SynthesisError::AssignmentMissing)?
        .insert(key, result.clone());
    Ok(result)
}

impl<F: PrimeField> Plan<F> {
    pub(super) fn transform(&self, values: &mut [F]) {
        if let Some(plan) = &self.six_step {
            plan.transform(values);
            return;
        }
        for stage in &self.inverse {
            stage.apply(values, true);
        }
        #[cfg(feature = "parallel")]
        values
            .par_iter_mut()
            .zip(&self.twist)
            .with_min_len(512)
            .for_each(|(value, twist)| *value *= twist);
        #[cfg(not(feature = "parallel"))]
        values
            .iter_mut()
            .zip(&self.twist)
            .for_each(|(value, twist)| *value *= twist);
        for stage in &self.forward {
            stage.apply(values, false);
        }
    }
}

impl<F: PrimeField> Stage<F> {
    fn apply(&self, values: &mut [F], inverse: bool) {
        let block_size = self.gap * 2;
        let tile_size = block_size.max(512);
        let apply_tile = |tile: &mut [F]| {
            for block in tile.chunks_mut(block_size) {
                let (lo, hi) = block.split_at_mut(self.gap);
                let butterfly = |((lo, hi), root): ((&mut F, &mut F), &F)| {
                    if inverse {
                        let left = *lo;
                        *lo += *hi;
                        *hi = (left - *hi) * root;
                    } else {
                        let right = *hi * root;
                        *hi = *lo - right;
                        *lo += right;
                    }
                };
                #[cfg(feature = "parallel")]
                if self.gap >= 1024 {
                    lo.par_iter_mut()
                        .zip(hi)
                        .zip(&self.roots)
                        .with_min_len(512)
                        .for_each(butterfly);
                } else {
                    lo.iter_mut().zip(hi).zip(&self.roots).for_each(butterfly);
                }
                #[cfg(not(feature = "parallel"))]
                lo.iter_mut().zip(hi).zip(&self.roots).for_each(butterfly);
            }
        };
        #[cfg(feature = "parallel")]
        values.par_chunks_mut(tile_size).for_each(apply_tile);
        #[cfg(not(feature = "parallel"))]
        values.chunks_mut(tile_size).for_each(apply_tile);
    }
}
