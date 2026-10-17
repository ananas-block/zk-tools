//! Internal BN254 verification using the proven mixed29/24-bit R=2^256 kernel.
//! Wire proofs and external verification continue to use the original ark types.
use ark_bn254::Fr;
use ark_ec::{
    bn::{Bn, BnConfig, TwistType},
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{
    AdditiveGroup, BigInt, Fp, Fp12Config, Fp2, Fp2Config, Fp6, Fp6Config, MontBackend, MontConfig,
};

type Fq = Fp<MontBackend<BaseConfig, 4>, 4>;
type Fq2 = Fp2<QuadraticConfig>;
type Fq6 = Fp6<SexticConfig>;
#[cfg(any(test, feature = "test-support"))]
type Fq12 = ark_ff::Fp12<TowerConfig>;
pub(super) type Engine = Bn<Config>;
pub(super) type Prepared = ark_groth16::PreparedVerifyingKey<Engine>;

pub(super) struct BaseConfig;
impl MontConfig<4> for BaseConfig {
    const MODULUS: BigInt<4> = <ark_bn254::FqConfig as MontConfig<4>>::MODULUS;
    const GENERATOR: Fq = field(<ark_bn254::FqConfig as MontConfig<4>>::GENERATOR);
    const TWO_ADIC_ROOT_OF_UNITY: Fq =
        field(<ark_bn254::FqConfig as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY);
    const SMALL_SUBGROUP_BASE: Option<u32> =
        <ark_bn254::FqConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE;
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> =
        <ark_bn254::FqConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE_ADICITY;
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Fq> =
        match <ark_bn254::FqConfig as MontConfig<4>>::LARGE_SUBGROUP_ROOT_OF_UNITY {
            Some(root) => Some(field(root)),
            None => None,
        };
    #[inline(always)]
    fn mul_assign(a: &mut Fq, b: &Fq) {
        a.0 = super::scalar_field::mont_products([a.0], [b.0], Self::MODULUS, Self::INV as u32);
    }
    #[inline(always)]
    fn square_in_place(a: &mut Fq) {
        a.0 = super::scalar_field::mont_products([a.0], [a.0], Self::MODULUS, Self::INV as u32);
    }
    #[inline(always)]
    fn sum_of_products<const M: usize>(a: &[Fq; M], b: &[Fq; M]) -> Fq {
        if M == 2 {
            return Fq::new_unchecked(super::scalar_field::mont_products(
                [a[0].0, a[1].0],
                [b[0].0, b[1].0],
                Self::MODULUS,
                Self::INV as u32,
            ));
        }
        a.iter().zip(b).map(|(a, b)| *a * b).sum()
    }
}
const fn field(value: ark_bn254::Fq) -> Fq {
    Fq::new_unchecked(value.0)
}
const fn quadratic(value: ark_bn254::Fq2) -> Fq2 {
    Fq2::new(field(value.c0), field(value.c1))
}
const fn sextic(value: ark_bn254::Fq6) -> Fq6 {
    Fq6::new(
        quadratic(value.c0),
        quadratic(value.c1),
        quadratic(value.c2),
    )
}
#[cfg(any(test, feature = "test-support"))]
const fn tower(value: ark_bn254::Fq12) -> Fq12 {
    Fq12::new(sextic(value.c0), sextic(value.c1))
}
const fn field_constants<const N: usize>(values: &[ark_bn254::Fq]) -> [Fq; N] {
    let mut out = [Fq::ZERO; N];
    let mut i = 0;
    while i < N {
        out[i] = field(values[i]);
        i += 1;
    }
    out
}
const fn quadratic_constants<const N: usize>(values: &[ark_bn254::Fq2]) -> [Fq2; N] {
    let mut out = [Fq2::ZERO; N];
    let mut i = 0;
    while i < N {
        out[i] = quadratic(values[i]);
        i += 1;
    }
    out
}
pub(super) struct QuadraticConfig;
impl Fp2Config for QuadraticConfig {
    type Fp = Fq;
    const NONRESIDUE: Fq = field(<ark_bn254::Fq2Config as Fp2Config>::NONRESIDUE);
    const FROBENIUS_COEFF_FP2_C1: &'static [Fq] =
        &field_constants::<2>(<ark_bn254::Fq2Config as Fp2Config>::FROBENIUS_COEFF_FP2_C1);
    #[inline(always)]
    fn mul_fp_by_nonresidue_in_place(value: &mut Fq) -> &mut Fq {
        value.neg_in_place()
    }
}
#[derive(Clone, Copy)]
pub(super) struct SexticConfig;
impl Fp6Config for SexticConfig {
    type Fp2Config = QuadraticConfig;
    const NONRESIDUE: Fq2 = quadratic(<ark_bn254::Fq6Config as Fp6Config>::NONRESIDUE);
    const FROBENIUS_COEFF_FP6_C1: &'static [Fq2] =
        &quadratic_constants::<6>(<ark_bn254::Fq6Config as Fp6Config>::FROBENIUS_COEFF_FP6_C1);
    const FROBENIUS_COEFF_FP6_C2: &'static [Fq2] =
        &quadratic_constants::<6>(<ark_bn254::Fq6Config as Fp6Config>::FROBENIUS_COEFF_FP6_C2);
    #[inline(always)]
    fn mul_fp2_by_nonresidue_in_place(value: &mut Fq2) -> &mut Fq2 {
        let f = value.double().double().double();
        *value = Fq2::new(f.c0 + value.c0 - value.c1, f.c1 + value.c1 + value.c0);
        value
    }
}
#[derive(Clone, Copy)]
pub(super) struct TowerConfig;
impl Fp12Config for TowerConfig {
    type Fp6Config = SexticConfig;
    const NONRESIDUE: Fq6 = sextic(<ark_bn254::Fq12Config as Fp12Config>::NONRESIDUE);
    const FROBENIUS_COEFF_FP12_C1: &'static [Fq2] =
        &quadratic_constants::<12>(<ark_bn254::Fq12Config as Fp12Config>::FROBENIUS_COEFF_FP12_C1);
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct G1Config;
impl CurveConfig for G1Config {
    type BaseField = Fq;
    type ScalarField = Fr;
    const COFACTOR: &'static [u64] = <ark_bn254::g1::Config as CurveConfig>::COFACTOR;
    const COFACTOR_INV: Fr = <ark_bn254::g1::Config as CurveConfig>::COFACTOR_INV;
}
impl SWCurveConfig for G1Config {
    const COEFF_A: Fq = field(<ark_bn254::g1::Config as SWCurveConfig>::COEFF_A);
    const COEFF_B: Fq = field(<ark_bn254::g1::Config as SWCurveConfig>::COEFF_B);
    const GENERATOR: Affine<Self> = Affine::new_unchecked(
        field(ark_bn254::g1::G1_GENERATOR_X),
        field(ark_bn254::g1::G1_GENERATOR_Y),
    );
    type ZeroFlag = ();
    #[inline(always)]
    fn mul_by_a(_: Fq) -> Fq {
        Fq::ZERO
    }
    fn is_in_correct_subgroup_assuming_on_curve(p: &Affine<Self>) -> bool {
        <ark_bn254::g1::Config as SWCurveConfig>::is_in_correct_subgroup_assuming_on_curve(
            &ark_bn254::G1Affine::new_unchecked(
                ark_bn254::Fq::new_unchecked(p.x.0),
                ark_bn254::Fq::new_unchecked(p.y.0),
            ),
        )
    }
}
#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct G2Config;
impl CurveConfig for G2Config {
    type BaseField = Fq2;
    type ScalarField = Fr;
    const COFACTOR: &'static [u64] = <ark_bn254::g2::Config as CurveConfig>::COFACTOR;
    const COFACTOR_INV: Fr = <ark_bn254::g2::Config as CurveConfig>::COFACTOR_INV;
}
impl SWCurveConfig for G2Config {
    const COEFF_A: Fq2 = quadratic(<ark_bn254::g2::Config as SWCurveConfig>::COEFF_A);
    const COEFF_B: Fq2 = quadratic(<ark_bn254::g2::Config as SWCurveConfig>::COEFF_B);
    const GENERATOR: Affine<Self> = Affine::new_unchecked(
        quadratic(ark_bn254::g2::G2_GENERATOR_X),
        quadratic(ark_bn254::g2::G2_GENERATOR_Y),
    );
    type ZeroFlag = ();
    #[inline(always)]
    fn mul_by_a(_: Fq2) -> Fq2 {
        Fq2::ZERO
    }
    fn is_in_correct_subgroup_assuming_on_curve(p: &Affine<Self>) -> bool {
        let original = |v: Fq2| {
            ark_bn254::Fq2::new(
                ark_bn254::Fq::new_unchecked(v.c0.0),
                ark_bn254::Fq::new_unchecked(v.c1.0),
            )
        };
        <ark_bn254::g2::Config as SWCurveConfig>::is_in_correct_subgroup_assuming_on_curve(
            &ark_bn254::G2Affine::new_unchecked(original(p.x), original(p.y)),
        )
    }
}
pub(super) struct Config;
impl BnConfig for Config {
    const X: &'static [u64] = <ark_bn254::Config as BnConfig>::X;
    const X_IS_NEGATIVE: bool = <ark_bn254::Config as BnConfig>::X_IS_NEGATIVE;
    const ATE_LOOP_COUNT: &'static [i8] = <ark_bn254::Config as BnConfig>::ATE_LOOP_COUNT;
    const TWIST_TYPE: TwistType = <ark_bn254::Config as BnConfig>::TWIST_TYPE;
    const TWIST_MUL_BY_Q_X: Fq2 = quadratic(<ark_bn254::Config as BnConfig>::TWIST_MUL_BY_Q_X);
    const TWIST_MUL_BY_Q_Y: Fq2 = quadratic(<ark_bn254::Config as BnConfig>::TWIST_MUL_BY_Q_Y);
    type Fp = Fq;
    type Fp2Config = QuadraticConfig;
    type Fp6Config = SexticConfig;
    type Fp12Config = TowerConfig;
    type G1Config = G1Config;
    type G2Config = G2Config;
}
fn g1(p: ark_bn254::G1Affine) -> Affine<G1Config> {
    Affine::new_unchecked(field(p.x), field(p.y))
}
fn g2(p: ark_bn254::G2Affine) -> Affine<G2Config> {
    Affine::new_unchecked(quadratic(p.x), quadratic(p.y))
}
pub(super) fn prepare(vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>) -> Prepared {
    ark_groth16::prepare_verifying_key(&ark_groth16::VerifyingKey {
        alpha_g1: g1(vk.alpha_g1),
        beta_g2: g2(vk.beta_g2),
        gamma_g2: g2(vk.gamma_g2),
        delta_g2: g2(vk.delta_g2),
        gamma_abc_g1: vk.gamma_abc_g1.iter().copied().map(g1).collect(),
    })
}
pub(super) fn verify(
    pvk: &Prepared,
    proof: &ark_groth16::Proof<ark_bn254::Bn254>,
    inputs: &[Fr],
) -> Result<bool, ark_relations::gr1cs::SynthesisError> {
    ark_groth16::Groth16::<Engine>::verify_proof(
        pvk,
        &ark_groth16::Proof {
            a: g1(proof.a),
            b: g2(proof.b),
            c: g1(proof.c),
        },
        inputs,
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "pairing_tests.rs"]
mod tests;

#[cfg(all(feature = "test-support", feature = "wasm", target_arch = "wasm32"))]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = wasmPairingSelfTest)]
pub fn self_test(mut seed: u32, count: u32) -> bool {
    use ark_ec::{pairing::Pairing, CurveGroup, PrimeGroup};
    use ark_ff::{Field, PrimeField};
    for i in 0..count {
        let mut next = || {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_exact_mut(4) {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                chunk.copy_from_slice(&seed.to_le_bytes());
            }
            ark_bn254::Fq::from_le_bytes_mod_order(&bytes)
        };
        let a = if i % 16 == 0 {
            ark_bn254::Fq::ZERO
        } else {
            next()
        };
        let b = if i % 17 == 0 {
            -ark_bn254::Fq::ONE
        } else {
            next()
        };
        let fa = field(a);
        let fb = field(b);
        if (fa * fb).0 != (a * b).0
            || fa.square().0 != a.square().0
            || Fq::sum_of_products(&[fa, fb], &[fb, fa]).0 != (a * b + b * a).0
        {
            return false;
        }
    }
    for mode in 0..8 {
        let scalar = Fr::from(u64::from(seed) + 1);
        let p = if mode % 3 == 0 {
            ark_bn254::G1Affine::identity()
        } else {
            (ark_bn254::G1Projective::generator() * scalar).into_affine()
        };
        let q = if mode % 4 == 0 {
            ark_bn254::G2Affine::identity()
        } else {
            (ark_bn254::G2Projective::generator() * (scalar + Fr::ONE)).into_affine()
        };
        if Engine::pairing(g1(p), g2(q)).0 != tower(ark_bn254::Bn254::pairing(p, q).0) {
            return false;
        }
        seed = seed.wrapping_add(0x9e3779b9);
    }
    true
}
