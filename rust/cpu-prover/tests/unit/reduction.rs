use super::*;
use ark_bn254::Fr;
use ark_ff::{One, UniformRand, Zero};
use ark_poly::GeneralEvaluationDomain;
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};

fn reference<F: PrimeField, D: EvaluationDomain<F>>(
    matrices: &[Matrix<F>],
    num_inputs: usize,
    num_constraints: usize,
    full_assignment: &[F],
) -> Result<Vec<F>, SynthesisError> {
    let [a, b, ..] = matrices else {
        return Err(SynthesisError::ArityMismatch);
    };
    let domain =
        D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let domain_size = domain.size();
    let inputs = full_assignment
        .get(..num_inputs)
        .ok_or(SynthesisError::AssignmentMissing)?;
    if a.len() < num_constraints || b.len() < num_constraints {
        return Err(SynthesisError::AssignmentMissing);
    }

    let rows = cfg_iter!(a)
        .zip(cfg_iter!(b))
        .take(num_constraints)
        .map(|(a_row, b_row)| {
            let a_value = evaluate(a_row, full_assignment)?;
            let b_value = evaluate(b_row, full_assignment)?;
            Ok((a_value, b_value, a_value * b_value))
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;
    let mut a = Vec::with_capacity(domain_size);
    let mut b = Vec::with_capacity(domain_size);
    let mut c = Vec::with_capacity(domain_size);
    for (a_value, b_value, c_value) in rows {
        a.push(a_value);
        b.push(b_value);
        c.push(c_value);
    }
    a.extend_from_slice(inputs);
    a.resize(domain_size, F::zero());
    b.resize(domain_size, F::zero());
    c.resize(domain_size, F::zero());

    let odd_coset_shift = D::new(2 * domain_size)
        .ok_or(SynthesisError::PolynomialDegreeTooLarge)?
        .element(1);
    for evaluations in [&mut a, &mut b, &mut c] {
        domain.ifft_in_place(evaluations);
        D::distribute_powers_and_mul_by_const(evaluations, odd_coset_shift, F::one());
        domain.fft_in_place(evaluations);
    }

    let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
    for (ab_i, c_i) in ab.iter_mut().zip(c) {
        *ab_i -= c_i;
    }
    Ok(ab)
}

#[test]
fn witness_map_scheduling_matches_original() {
    let mut rng = StdRng::seed_from_u64(0xae610_u64);
    for constraints in [1, 7, 61, 257, 1023, 5641, 13699] {
        for mode in 0..4 {
            let assignment: Vec<Fr> = (0..37)
                .map(|_| match mode {
                    0 => Fr::zero(),
                    1 => Fr::one(),
                    2 => Fr::from(rng.gen_range(0_u64..256)),
                    _ => Fr::rand(&mut rng),
                })
                .collect();
            let matrices: Vec<Matrix<Fr>> = (0..2)
                .map(|_| {
                    (0..constraints)
                        .map(|_| {
                            (0..rng.gen_range(0..8))
                                .map(|_| (Fr::rand(&mut rng), rng.gen_range(0..assignment.len())))
                                .collect()
                        })
                        .collect()
                })
                .collect();
            let expected = reference::<Fr, GeneralEvaluationDomain<Fr>>(
                &matrices,
                3,
                constraints,
                &assignment,
            )
            .expect("reference");
            let actual = CircomReduction::witness_map_from_matrices::<
                Fr,
                GeneralEvaluationDomain<Fr>,
            >(&matrices, 3, constraints, &assignment)
            .expect("candidate");
            assert_eq!(actual, expected, "constraints={constraints}, mode={mode}");
        }
    }
}
