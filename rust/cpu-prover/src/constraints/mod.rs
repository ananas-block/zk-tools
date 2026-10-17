mod compiled;

use self::compiled::CompiledMatrices;
use crate::Error;
use ark_bn254::Fr;
use ark_ff::One;
#[cfg(feature = "setup")]
use ark_ff::Zero;
use ark_relations::gr1cs::Matrix;
#[cfg(feature = "setup")]
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystemRef as CircuitSystem, SynthesisError,
};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub struct R1csMatrices {
    matrices: [Matrix<Fr>; 3],
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub num_constraints: usize,
}

impl R1csMatrices {
    pub fn new(
        matrices: [Matrix<Fr>; 3],
        num_instance_variables: usize,
        num_witness_variables: usize,
        num_constraints: usize,
    ) -> Self {
        Self {
            matrices,
            num_instance_variables,
            num_witness_variables,
            num_constraints,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.num_instance_variables == 0
            || self
                .num_instance_variables
                .checked_add(self.num_witness_variables)
                .is_none()
            || self
                .num_constraints
                .checked_add(self.num_instance_variables)
                .is_none()
            || [self.a(), self.b(), self.c()]
                .iter()
                .any(|m| m.len() != self.num_constraints)
        {
            return Err(Error::InvalidMatrices(
                "invalid counts or matrix row lengths",
            ));
        }
        Ok(())
    }

    pub fn a(&self) -> &Matrix<Fr> {
        &self.matrices[0]
    }

    pub fn b(&self) -> &Matrix<Fr> {
        &self.matrices[1]
    }

    pub fn c(&self) -> &Matrix<Fr> {
        &self.matrices[2]
    }
}

#[cfg(feature = "setup")]
pub(crate) struct Replay<'a>(pub(crate) &'a R1csMatrices);

#[cfg(feature = "setup")]
impl ConstraintSynthesizer<Fr> for Replay<'_> {
    fn generate_constraints(self, cs: CircuitSystem<Fr>) -> Result<(), SynthesisError> {
        use ark_relations::gr1cs::{LinearCombination, Variable};

        let instance = self.0.num_instance_variables;
        for _ in 1..instance {
            let _ = cs.new_input_variable(|| Ok(Fr::zero()))?;
        }
        for _ in 0..self.0.num_witness_variables {
            let _ = cs.new_witness_variable(|| Ok(Fr::zero()))?;
        }
        let variable = |index: usize| match index {
            0 => Variable::One,
            index if index < instance => Variable::instance(index),
            index => Variable::witness(index - instance),
        };
        let lc = |row: &[(Fr, usize)]| {
            LinearCombination(
                row.iter()
                    .map(|(coefficient, index)| (*coefficient, variable(*index)))
                    .collect(),
            )
        };
        for (a, b, c) in rows(self.0) {
            cs.enforce_r1cs_constraint(|| lc(a), || lc(b), || lc(c))?;
        }
        Ok(())
    }
}

/// Immutable expression plan, reusable across proofs; evaluated values stay per call.
pub struct PreparedMatrices {
    matrices: R1csMatrices,
    compiled: CompiledMatrices,
}

impl PreparedMatrices {
    pub fn new(matrices: R1csMatrices) -> Result<Self, Error> {
        matrices.validate()?;
        let compiled = CompiledMatrices::new(&matrices);
        Ok(Self { matrices, compiled })
    }

    pub fn matrices(&self) -> &R1csMatrices {
        &self.matrices
    }

    pub(crate) fn evaluate_checked(&self, assignment: &[Fr]) -> Result<[Vec<Fr>; 3], Error> {
        let variables = self.matrices.num_instance_variables + self.matrices.num_witness_variables;
        if assignment.len() != variables || assignment.first() != Some(&Fr::one()) {
            return Err(Error::ProofInputsForAnotherCircuit);
        }
        let values = self.compiled.evaluate(assignment);
        let check =
            |(row, ids): (usize, &[usize; 3])| match CompiledMatrices::values_for(ids, &values) {
                Some([a, b, c]) if a * b == c => None,
                Some(_) => Some(Error::UnsatisfiedConstraint { row }),
                None => Some(Error::ProofInputsForAnotherCircuit),
            };
        #[cfg(feature = "parallel")]
        let failure = self
            .compiled
            .row_ids()
            .par_iter()
            .enumerate()
            .find_map_first(check);
        #[cfg(not(feature = "parallel"))]
        let failure = self.compiled.row_ids().iter().enumerate().find_map(check);
        if let Some(error) = failure {
            return Err(error);
        }
        let mut a = Vec::with_capacity(self.matrices.num_constraints);
        let mut b = Vec::with_capacity(self.matrices.num_constraints);
        let mut c = Vec::with_capacity(self.matrices.num_constraints);
        for row in self.compiled.rows(&values) {
            let [av, bv, cv] = row.ok_or(Error::ProofInputsForAnotherCircuit)?;
            a.push(av);
            b.push(bv);
            c.push(cv);
        }
        Ok([a, b, c])
    }

    pub fn check(&self, assignment: &[Fr]) -> Result<(), Error> {
        self.evaluate_checked(assignment).map(|_| ())
    }
}

#[cfg(feature = "setup")]
fn rows(
    matrices: &R1csMatrices,
) -> impl Iterator<Item = (&[(Fr, usize)], &[(Fr, usize)], &[(Fr, usize)])> {
    matrices
        .a()
        .iter()
        .zip(matrices.b())
        .zip(matrices.c())
        .map(|((a, b), c)| (a.as_slice(), b.as_slice(), c.as_slice()))
}
