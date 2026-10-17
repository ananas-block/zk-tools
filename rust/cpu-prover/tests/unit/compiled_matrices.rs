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
