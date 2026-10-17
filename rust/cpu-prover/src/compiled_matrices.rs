use std::collections::HashMap;

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use ark_std::cfg_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::matrices::R1csMatrices;

/// Matrix expressions are immutable. Their values belong to one proof only.
pub(super) struct CompiledMatrices {
    expressions: Vec<Expression>,
    rows: Vec<[usize; 3]>,
}

struct Expression {
    positive: Vec<usize>,
    negative: Vec<usize>,
    scaled: Vec<(Fr, usize)>,
}

impl Expression {
    fn new(terms: &[(Fr, usize)]) -> Self {
        let mut result = Self {
            positive: Vec::new(),
            negative: Vec::new(),
            scaled: Vec::new(),
        };
        let negative_one = -Fr::one();
        for (coefficient, variable) in terms {
            if coefficient.is_one() {
                result.positive.push(*variable);
            } else if *coefficient == negative_one {
                result.negative.push(*variable);
            } else {
                result.scaled.push((*coefficient, *variable));
            }
        }
        result
    }

    fn evaluate(&self, assignment: &[Fr]) -> Option<Fr> {
        let sum = self.positive.iter().try_fold(Fr::zero(), |sum, variable| {
            Some(sum + assignment.get(*variable)?)
        })?;
        let sum = self
            .negative
            .iter()
            .try_fold(sum, |sum, variable| Some(sum - assignment.get(*variable)?))?;
        self.scaled
            .iter()
            .try_fold(sum, |sum, (coefficient, variable)| {
                Some(sum + *coefficient * assignment.get(*variable)?)
            })
    }
}

impl CompiledMatrices {
    pub(super) fn new<'a>(matrices: &'a R1csMatrices) -> Self {
        let mut ids: HashMap<&'a [(Fr, usize)], usize> = HashMap::new();
        let mut expressions = Vec::new();
        let mut intern = |row: &'a [(Fr, usize)]| {
            if let Some(id) = ids.get(row) {
                *id
            } else {
                let id = expressions.len();
                expressions.push(Expression::new(row));
                ids.insert(row, id);
                id
            }
        };
        let rows = matrices
            .a()
            .iter()
            .zip(matrices.b())
            .zip(matrices.c())
            .map(|((a, b), c)| [intern(a), intern(b), intern(c)])
            .collect();
        Self { expressions, rows }
    }

    pub(super) fn evaluate(&self, assignment: &[Fr]) -> Vec<Option<Fr>> {
        cfg_iter!(self.expressions)
            .map(|expression| expression.evaluate(assignment))
            .collect()
    }

    pub(super) fn rows<'a>(
        &'a self,
        values: &'a [Option<Fr>],
    ) -> impl Iterator<Item = Option<[Fr; 3]>> + 'a {
        self.rows.iter().map(|row| Self::values_for(row, values))
    }
    pub(super) fn row_ids(&self) -> &[[usize; 3]] {
        &self.rows
    }

    pub(super) fn values_for([a, b, c]: &[usize; 3], values: &[Option<Fr>]) -> Option<[Fr; 3]> {
        Some([
            values.get(*a).copied().flatten()?,
            values.get(*b).copied().flatten()?,
            values.get(*c).copied().flatten()?,
        ])
    }
}

#[cfg(all(test, feature = "setup", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn shared_expressions_match_reference_for_fresh_assignments() {
        let mut rng = StdRng::seed_from_u64(0xcac4e);
        let patterns: Vec<Vec<_>> = (0..11)
            .map(|pattern| {
                (0..9)
                    .map(|term| {
                        let coefficient = match term % 3 {
                            0 => Fr::one(),
                            1 => -Fr::one(),
                            _ => Fr::rand(&mut rng),
                        };
                        (coefficient, (pattern + term) % 17)
                    })
                    .collect()
            })
            .collect();
        let a: Vec<_> = patterns.iter().cycle().take(73).cloned().collect();
        let b = vec![vec![(Fr::one(), 0)]; a.len()];
        let matrices = R1csMatrices::new([a.clone(), b, a], 1, 16, 73);
        let compiled = CompiledMatrices::new(&matrices);
        assert_eq!(compiled.expressions.len(), 12);
        let mut previous = None;
        for mode in 0..10 {
            let assignment: Vec<_> = (0..17)
                .map(|index| {
                    if index == 0 {
                        Fr::one()
                    } else if mode == 0 {
                        Fr::zero()
                    } else if mode == 1 {
                        Fr::one()
                    } else {
                        Fr::rand(&mut rng)
                    }
                })
                .collect();
            let values = compiled.evaluate(&assignment);
            let actual: Vec<_> = compiled.rows(&values).collect();
            let reference = |row: &Vec<(Fr, usize)>| {
                row.iter().fold(Fr::zero(), |sum, (coefficient, variable)| {
                    sum + *coefficient * assignment.get(*variable).expect("valid test index")
                })
            };
            let expected: Vec<_> = matrices
                .a()
                .iter()
                .zip(matrices.b())
                .zip(matrices.c())
                .map(|((a, b), c)| Some([reference(a), reference(b), reference(c)]))
                .collect();
            assert_eq!(actual, expected, "assignment mode {mode}");
            if let Some(previous) = previous {
                assert_ne!(
                    actual, previous,
                    "a new assignment must not reuse witness values"
                );
            }
            previous = Some(actual);
        }
    }
}
