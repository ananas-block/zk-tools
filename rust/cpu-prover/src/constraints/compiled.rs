use std::collections::HashMap;

use ark_bn254::Fr;
use ark_ff::{One, Zero};
use ark_std::cfg_iter;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::R1csMatrices;

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
#[path = "../../tests/unit/compiled_matrices.rs"]
mod tests;
