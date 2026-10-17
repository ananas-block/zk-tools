//! Portable BN254 scalar arithmetic for the WASM coset transform.
//! The mixed29/24-bit radix preserves arkworks Montgomery R=2^256.
use ark_bn254::Fr;
use ark_ff::{BigInt, Fp, MontBackend, MontConfig};
pub(crate) type Scalar = Fp<MontBackend<FrConfig, 4>, 4>;

pub(crate) struct FrConfig;

impl MontConfig<4> for FrConfig {
    const MODULUS: BigInt<4> = <ark_bn254::FrConfig as MontConfig<4>>::MODULUS;
    const GENERATOR: Scalar = from_ark(<ark_bn254::FrConfig as MontConfig<4>>::GENERATOR);
    const TWO_ADIC_ROOT_OF_UNITY: Scalar =
        from_ark(<ark_bn254::FrConfig as MontConfig<4>>::TWO_ADIC_ROOT_OF_UNITY);
    const SMALL_SUBGROUP_BASE: Option<u32> =
        <ark_bn254::FrConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE;
    const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> =
        <ark_bn254::FrConfig as MontConfig<4>>::SMALL_SUBGROUP_BASE_ADICITY;
    const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<Scalar> =
        match <ark_bn254::FrConfig as MontConfig<4>>::LARGE_SUBGROUP_ROOT_OF_UNITY {
            Some(root) => Some(from_ark(root)),
            None => None,
        };
    #[inline(always)]
    fn mul_assign(a: &mut Scalar, b: &Scalar) {
        a.0 = mont_products([a.0], [b.0], Self::MODULUS, Self::INV as u32);
    }
    #[inline(always)]
    fn square_in_place(a: &mut Scalar) {
        a.0 = mont_products([a.0], [a.0], Self::MODULUS, Self::INV as u32);
    }
    #[inline(always)]
    fn sum_of_products<const M: usize>(a: &[Scalar; M], b: &[Scalar; M]) -> Scalar {
        if M == 2 {
            return Scalar::new_unchecked(mont_products(
                [a[0].0, a[1].0],
                [b[0].0, b[1].0],
                Self::MODULUS,
                Self::INV as u32,
            ));
        }
        a.iter().zip(b).map(|(a, b)| *a * b).sum()
    }
}

pub(crate) const fn from_ark(value: Fr) -> Scalar {
    Scalar::new_unchecked(value.0)
}

// Execute the optimized scalar kernel and coset transform in the browser too;
// native tests cannot expose a WASM engine or postlink miscompilation.
#[cfg(all(target_arch = "wasm32", feature = "wasm", feature = "test-support"))]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = wasmScalarSelfTest)]
pub fn scalar_self_test(mut seed: u32, count: u32) -> bool {
    use ark_ff::{AdditiveGroup, Field, PrimeField};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

    let mut random = || {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_exact_mut(4) {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            chunk.copy_from_slice(&seed.to_le_bytes());
        }
        Fr::from_le_bytes_mod_order(&bytes)
    };
    for index in 0..count {
        let a = match index % 8 {
            0 => Fr::ZERO,
            1 => Fr::ONE,
            2 => -Fr::ONE,
            _ => random(),
        };
        let b = random();
        let (fa, fb) = (from_ark(a), from_ark(b));
        if (fa * fb).0 != (a * b).0
            || fa.square().0 != a.square().0
            || Scalar::sum_of_products(&[fa, fb], &[fb, fa]).0 != (a * b + b * a).0
        {
            return false;
        }
    }
    for length in [1, 2, 8, 64, 1024, 8192] {
        let Some(reference) = GeneralEvaluationDomain::<Fr>::new_coset(length, Fr::from(5u64))
        else {
            return false;
        };
        let Some(optimized) =
            GeneralEvaluationDomain::<Scalar>::new_coset(length, from_ark(Fr::from(5u64)))
        else {
            return false;
        };
        let values: Vec<_> = (0..length).map(|_| random()).collect();
        let mut expected = values.clone();
        let mut actual: Vec<_> = values.iter().copied().map(from_ark).collect();
        reference.fft_in_place(&mut expected);
        optimized.fft_in_place(&mut actual);
        if expected.iter().zip(&actual).any(|(a, b)| a.0 != b.0) {
            return false;
        }
        optimized.ifft_in_place(&mut actual);
        if values.iter().zip(&actual).any(|(a, b)| a.0 != b.0) {
            return false;
        }
    }
    true
}

#[cfg(all(target_arch = "wasm32", feature = "wasm", feature = "test-support"))]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = wasmScalarFixture)]
pub fn scalar_fixture(a: &[u8], b: &[u8]) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
    use ark_ff::{BigInteger, PrimeField};
    if a.len() != 32 || b.len() != 32 {
        return Err(wasm_bindgen::JsValue::from_str(
            "scalar fixtures require two 32-byte inputs",
        ));
    }
    let a = from_ark(Fr::from_le_bytes_mod_order(a));
    let b = from_ark(Fr::from_le_bytes_mod_order(b));
    Ok((a * b).into_bigint().to_bytes_le())
}

#[inline(always)]
const fn split29(a: BigInt<4>) -> [u64; 9] {
    const MASK: u64 = (1 << 29) - 1;
    [
        a.0[0] & MASK,
        (a.0[0] >> 29) & MASK,
        ((a.0[0] >> 58) | (a.0[1] << 6)) & MASK,
        (a.0[1] >> 23) & MASK,
        ((a.0[1] >> 52) | (a.0[2] << 12)) & MASK,
        (a.0[2] >> 17) & MASK,
        ((a.0[2] >> 46) | (a.0[3] << 18)) & MASK,
        (a.0[3] >> 11) & MASK,
        a.0[3] >> 40,
    ]
}

#[inline(always)]
pub(crate) fn mont_products<const M: usize>(
    a: [BigInt<4>; M],
    b: [BigInt<4>; M],
    modulus: BigInt<4>,
    inverse: u32,
) -> BigInt<4> {
    const MASK: u64 = (1 << 29) - 1;
    const FINAL_MASK: u64 = (1 << 24) - 1;
    let a = a.map(split29);
    let b = b.map(split29);
    let q = split29(modulus);
    let mut t = [0u64; 9];
    // Nine rounds accumulate at most 9*(M+1) products in any word. M=1 or2
    // bounds each word below 27*2^58, hence below 2^63. Carries fit in u64.
    macro_rules! round { ($i:expr) => {{
        let i = $i;
        let mut lo = t[0];
        for (a, b) in a.iter().zip(&b) {
            lo += a[i] * b[0];
        }
        let m = lo.wrapping_mul(u64::from(inverse)) & MASK;
        let carry = (lo + m * q[0]) >> 29;
        for j in 1..9 {
            let mut v = t[j] + m * q[j];
            for (a, b) in a.iter().zip(&b) {
                v += a[i] * b[j];
            }
            if j == 1 {
                v += carry;
            }
            t[j - 1] = v;
        }
        t[8] = 0;
    }}; }
    for i in 0..8 {
        round!(i);
    }
    // Final operand limb is at most 22 bits for BN254. The final24-bit
    // reduction finishes the exact 256-bit Montgomery radix.
    let mut lo = t[0];
    for (a, b) in a.iter().zip(&b) {
        lo += a[8] * b[0];
    }
    let m = lo.wrapping_mul(u64::from(inverse)) & FINAL_MASK;
    let mut words = [0u64; 10];
    let mut carry = 0;
    for j in 0..9 {
        let mut v = t[j] + m * q[j] + carry;
        for (a, b) in a.iter().zip(&b) {
            v += a[8] * b[j];
        }
        words[j] = v & MASK;
        carry = v >> 29;
    }
    words[9] = carry;
    // Pack normalized29-bit digits after division by2^24.
    let mut result = BigInt([
        (words[0] >> 24) | (words[1] << 5) | (words[2] << 34) | (words[3] << 63),
        (words[3] >> 1) | (words[4] << 28) | (words[5] << 57),
        (words[5] >> 7) | (words[6] << 22) | (words[7] << 51),
        (words[7] >> 13) | (words[8] << 16) | (words[9] << 45),
    ]);
    // With a_i,b_i<q<R/4, sum(A_i*B_i)/R+q < (M/4+1)q <2q.
    if result >= modulus {
        use ark_ff::BigInteger;
        result.sub_with_borrow(&modulus);
    }
    result
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../../tests/unit/scalar_field.rs"]
mod tests;
