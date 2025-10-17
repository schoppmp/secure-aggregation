// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use kahe::KahePublicParametersWrapper;
use kahe_traits::{
    KaheBase, KaheDecrypt, KaheEncrypt, KaheKeygen, TrySecretKeyFrom, TrySecretKeyInto,
};
use shell_types::{
    add_in_place, add_in_place_vec, read_small_rns_polynomial_from_buffer,
    write_small_rns_polynomial_to_buffer, RnsPolynomial, RnsPolynomialVec,
};
use single_thread_hkdf::{Seed, SingleThreadHkdfPrng};

/// Number of bits supported by the C++ big integer type used for KAHE
/// plaintext.
const BIG_INT_BITS: u64 = 256;

/// Stores parameters to create a new RNS context for KAHE.
#[derive(Debug, Clone)]
pub struct KaheRnsConfig {
    pub log_n: u64,
    pub log_t: u64,
    pub qs: Vec<u64>,
}

/// ShellKahe configuration. For a fixed RNS context, we can have multiple
/// values for the other parameters (e.g. short or long inputs, or different
/// combinations of packing_base/num_packing that fit within the same plaintext
/// modulus). Can only be created with valid parameters from outside this crate.
#[derive(Debug, Clone)]
pub struct ShellKaheConfig {
    pub input_domain: u64,
    pub max_num_clients: usize,
    pub num_public_polynomials: usize,
    pub rns_config: KaheRnsConfig,
    pub(crate) packing_base: u64,
    pub(crate) num_packing: usize,
}

impl ShellKaheConfig {
    /// Validates parameters and creates a new ShellKaheConfig instance.
    pub fn new(
        input_domain: u64,
        max_num_clients: usize,
        num_packing: usize,
        num_public_polynomials: usize,
        rns_config: KaheRnsConfig,
    ) -> Result<Self, status::StatusError> {
        if num_packing == 0 {
            return Err(status::invalid_argument("num_packing must be > 0"));
        }
        // B = n * t
        let packing_base = input_domain * max_num_clients as u64;
        if packing_base <= 1 {
            return Err(status::invalid_argument("packing_base must be > 1"));
        }
        if rns_config.log_t > BIG_INT_BITS {
            return Err(status::invalid_argument(format!(
                "log_t must be <= {} for plaintexts to fit in the C++ big integer type, got {}",
                BIG_INT_BITS, rns_config.log_t
            )));
        }
        let log_packing_base = (packing_base as f64).log2().ceil() as u64;
        if (num_packing as u64) * log_packing_base > rns_config.log_t {
            return Err(status::invalid_argument(format!(
                "packing_base^num_packing must not be larger than the KAHE plaintext modulus 2^log_t: packing_base = {}, num_packing = {}, log_t = {}", packing_base, num_packing, rns_config.log_t
            )));
        }
        Ok(Self {
            input_domain,
            max_num_clients,
            num_public_polynomials,
            rns_config,
            packing_base,
            num_packing,
        })
    }
}

/// Base type holding public KAHE configuration and C++ parameters.
pub struct ShellKahe {
    input_domain: u64,
    packing_base: u64,
    num_packing: usize,
    rns_config: KaheRnsConfig,
    public_kahe_parameters: KahePublicParametersWrapper,
}

impl ShellKahe {
    /// Creates a new ShellKahe instance.
    pub fn new(config: ShellKaheConfig, public_seed: &Seed) -> Result<Self, status::StatusError> {
        let public_kahe_parameters = kahe::create_public_parameters(
            config.rns_config.log_n,
            config.rns_config.log_t,
            &config.rns_config.qs,
            config.num_public_polynomials,
            &public_seed,
        )?;
        Ok(Self {
            input_domain: config.input_domain,
            packing_base: config.packing_base,
            num_packing: config.num_packing,
            rns_config: config.rns_config,
            public_kahe_parameters,
        })
    }
}

impl KaheBase for ShellKahe {
    type SecretKey = RnsPolynomial;

    type Plaintext = Vec<u64>;

    type Ciphertext = RnsPolynomialVec;

    type Rng = SingleThreadHkdfPrng;

    fn add_keys_in_place(
        &self,
        left: &Self::SecretKey,
        right: &mut Self::SecretKey,
    ) -> Result<(), status::StatusError> {
        // NOTE: This is just calling `MakeSpan` on an existing vector of raw pointers
        // that lives in `public_kahe_parameters`.
        let moduli = kahe::get_moduli(&self.public_kahe_parameters);
        add_in_place(&moduli, left, right)?;
        Ok(())
    }

    fn add_plaintexts_in_place(
        &self,
        left: &Self::Plaintext,
        right: &mut Self::Plaintext,
    ) -> Result<(), status::StatusError> {
        if left.len() != right.len() {
            return Err(status::invalid_argument(format!(
                "left and right must have the same length, got {} and {}",
                left.len(),
                right.len()
            )));
        }
        for (i, v) in left.iter().enumerate() {
            right[i] += v;
        }
        Ok(())
    }

    fn add_ciphertexts_in_place(
        &self,
        left: &Self::Ciphertext,
        right: &mut Self::Ciphertext,
    ) -> Result<(), status::StatusError> {
        let moduli = kahe::get_moduli(&self.public_kahe_parameters);
        add_in_place_vec(&moduli, left, right)?;
        Ok(())
    }
}

impl KaheKeygen for ShellKahe {
    fn key_gen(&self, r: &mut Self::Rng) -> Result<Self::SecretKey, status::StatusError> {
        kahe::generate_secret_key(&self.public_kahe_parameters, &mut r.0)
    }
}

impl KaheEncrypt for ShellKahe {
    fn encrypt(
        &self,
        pt: &Self::Plaintext,
        sk: &Self::SecretKey,
        r: &mut Self::Rng,
    ) -> Result<Self::Ciphertext, status::StatusError> {
        // Check that inputs are valid to avoid packing and plaintext overflow errors.
        for v in pt.iter() {
            if *v >= self.input_domain {
                return Err(status::invalid_argument(format!(
                    "plaintext value {} is larger than the input domain {}",
                    *v, self.input_domain
                )));
            }
        }

        kahe::encrypt(
            &pt[..],
            &sk,
            &self.public_kahe_parameters,
            self.packing_base,
            self.num_packing,
            &mut r.0,
        )
    }
}

impl KaheDecrypt for ShellKahe {
    fn decrypt(
        &self,
        ct: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Result<Self::Plaintext, status::StatusError> {
        // Allocate the right number of values to hold an unpacked and padded output.
        let num_coeffs = 1 << self.rns_config.log_n;
        let num_values = num_coeffs * self.num_packing * (ct.len as usize);
        let mut output_values = vec![0; num_values];

        // Decrypt into the buffer.
        let n_written = kahe::decrypt(
            &ct,
            &sk,
            &self.public_kahe_parameters,
            self.packing_base,
            self.num_packing,
            &mut output_values[..],
        )?;

        if n_written != num_values {
            return Err(status::internal(format!(
                "Expected {} decrypted values, but got {}.",
                num_values, n_written
            )));
        }
        Ok(output_values)
    }
}

impl TrySecretKeyInto<Vec<i64>> for ShellKahe {
    fn try_secret_key_into(&self, sk: Self::SecretKey) -> Result<Vec<i64>, status::StatusError> {
        let num_coeffs = 1 << self.rns_config.log_n;
        let mut signed_values: Vec<i64> = vec![0; num_coeffs];
        let moduli = kahe::get_moduli(&self.public_kahe_parameters);

        let n_written = write_small_rns_polynomial_to_buffer(&sk, &moduli, &mut signed_values[..])?;
        if n_written != num_coeffs {
            return Err(status::internal(format!(
                "Expected {} coefficients, but got {}.",
                num_coeffs, n_written
            )));
        }

        return Ok(signed_values);
    }
}

impl TrySecretKeyFrom<Vec<i64>> for ShellKahe {
    fn try_secret_key_from(
        &self,
        sk_buffer: Vec<i64>,
    ) -> Result<Self::SecretKey, status::StatusError> {
        let log_n = self.rns_config.log_n as usize;
        if sk_buffer.len() < log_n {
            return Err(status::invalid_argument(format!(
                "secret key buffer is too short: {} < {}",
                sk_buffer.len(),
                self.rns_config.log_n
            )));
        }

        let moduli = kahe::get_moduli(&self.public_kahe_parameters);
        let num_coeffs = 1 << log_n;
        let poly = read_small_rns_polynomial_from_buffer(
            &sk_buffer[..num_coeffs], // Remove potential padding from AHE decryption.
            self.rns_config.log_n,
            &moduli,
        )?;
        Ok(poly)
    }
}

#[cfg(test)]
mod test {
    // Instead of `super::*` because we consume types from other testing crates.
    use kahe_shell::*;

    /// Standard deviation of the discrete Gaussian distribution used for
    /// secret key generation. Hardcoded in shell_wrapper/kahe.h for now (if we ever
    /// need to change it then we can pass it from Rust like we do in shell/ahe.rs).
    const SECRET_KEY_STD: f64 = 4.5;

    /// The tail bound cut-off multiplier such that the probability of a sample
    /// of DG_s being outside of [+/- `kTailBoundMultiplier` * s] is
    /// negligible. See rlwe/sampler/discrete_gaussian.h.
    const TAIL_BOUND_MULTIPLIER: f64 = 8.0;

    /// Tail bound for the case of a single secret key.
    const TAIL_BOUND: i64 = (TAIL_BOUND_MULTIPLIER * SECRET_KEY_STD + 1.0) as i64;

    use googletest::{gtest, verify_eq, verify_le, verify_that};
    use kahe_traits::{
        KaheBase, KaheDecrypt, KaheEncrypt, KaheKeygen, TrySecretKeyFrom, TrySecretKeyInto,
    };
    use prng_traits::SecurePrng;
    use shell_testing_parameters::make_kahe_rns_config;
    use single_thread_hkdf::SingleThreadHkdfPrng;
    use testing_utils::generate_random_unsigned_vector;

    #[gtest]
    fn test_encrypt_decrypt_short() -> googletest::Result<()> {
        let plaintext_modulus_bits = 39;
        let input_domain = 10;
        let max_num_clients = 100;
        let num_packing = 2;
        let num_public_polynomials = 1;
        let rns_config = make_kahe_rns_config(plaintext_modulus_bits)?;
        let kahe_config = ShellKaheConfig::new(
            input_domain,
            max_num_clients,
            num_packing,
            num_public_polynomials,
            rns_config.clone(),
        )?;
        let public_seed = SingleThreadHkdfPrng::generate_seed()?;
        let kahe = ShellKahe::new(kahe_config, &public_seed)?;

        let pt = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let sk = kahe.key_gen(&mut prng)?;
        let ct = kahe.encrypt(&pt, &sk, &mut prng)?;
        let decrypted = kahe.decrypt(&ct, &sk)?;
        verify_eq!(&pt, &decrypted[..pt.len()])
    }

    #[gtest]
    fn test_encrypt_decrypt_with_serialized_key() -> googletest::Result<()> {
        let plaintext_modulus_bits = 39;
        let input_domain = 10;
        let max_num_clients = 100;
        let num_packing = 2;
        let num_public_polynomials = 1;
        let rns_config = make_kahe_rns_config(plaintext_modulus_bits)?;
        let kahe_config = ShellKaheConfig::new(
            input_domain,
            max_num_clients,
            num_packing,
            num_public_polynomials,
            rns_config.clone(),
        )?;
        let public_seed = SingleThreadHkdfPrng::generate_seed()?;
        let kahe = ShellKahe::new(kahe_config, &public_seed)?;

        let pt = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let sk = kahe.key_gen(&mut prng)?;
        let ct = kahe.encrypt(&pt, &sk, &mut prng)?;

        // Serialize the key and deserialize it.
        let sk_buffer = kahe.try_secret_key_into(sk)?;
        let sk_recovered = kahe.try_secret_key_from(sk_buffer)?;

        // Check that the decrypted value is the same as the original plaintext.
        let decrypted = kahe.decrypt(&ct, &sk_recovered)?;
        verify_eq!(&pt, &decrypted[..pt.len()])
    }

    #[gtest]
    fn test_encrypt_decrypt_long() -> googletest::Result<()> {
        let plaintext_modulus_bits = 17;
        let input_domain = 5;
        let max_num_clients = 1000;
        let num_packing = 1;
        let num_public_polynomials = 2;
        let rns_config = make_kahe_rns_config(plaintext_modulus_bits)?;
        let kahe_config = ShellKaheConfig::new(
            input_domain,
            max_num_clients,
            num_packing,
            num_public_polynomials,
            rns_config.clone(),
        )?;
        let public_seed = SingleThreadHkdfPrng::generate_seed()?;
        let kahe = ShellKahe::new(kahe_config, &public_seed)?;

        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let sk = kahe.key_gen(&mut prng)?;

        // Generate a random vector, encrypt and decrypt it.
        let num_messages = (1 << rns_config.log_n) * 2; // Needs two polynomials.
        let pt = generate_random_unsigned_vector(num_messages, input_domain);
        let ct = kahe.encrypt(&pt, &sk, &mut prng)?;
        let decrypted = kahe.decrypt(&ct, &sk)?;
        verify_eq!(pt, decrypted) // Both vectors are padded to the same length.
    }

    /// Check homomorphic addition of two inputs.
    #[gtest]
    fn add_two_inputs() -> googletest::Result<()> {
        let plaintext_modulus_bits = 93;
        let input_domain = 10;
        let max_num_clients = 2;
        let num_packing = 1;
        let num_public_polynomials = 2;
        let rns_config = make_kahe_rns_config(plaintext_modulus_bits)?;
        let kahe_config = ShellKaheConfig::new(
            input_domain,
            max_num_clients,
            num_packing,
            num_public_polynomials,
            rns_config.clone(),
        )?;
        let public_seed = SingleThreadHkdfPrng::generate_seed()?;
        let kahe = ShellKahe::new(kahe_config, &public_seed)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;

        let num_messages = 50;

        // Client 1
        let sk1 = kahe.key_gen(&mut prng)?;
        let pt1 = generate_random_unsigned_vector(num_messages, input_domain);
        let ct1 = kahe.encrypt(&pt1, &sk1, &mut prng)?;

        // Client 2
        let mut sk2 = kahe.key_gen(&mut prng)?;
        let mut pt2 = generate_random_unsigned_vector(num_messages, input_domain);
        let mut ct2 = kahe.encrypt(&pt2, &sk2, &mut prng)?;

        // Decryptor adds up keys
        kahe.add_keys_in_place(&sk1, &mut sk2)?;

        // Server adds ciphertexts and uses aggregated key to decrypt.
        kahe.add_ciphertexts_in_place(&ct1, &mut ct2)?;
        let pt_sum = kahe.decrypt(&ct2, &sk2)?;
        kahe.add_plaintexts_in_place(&pt1, &mut pt2)?;
        verify_eq!(&pt2, &pt_sum[..num_messages])
    }

    #[gtest]
    fn read_write_secret_key() -> googletest::Result<()> {
        let plaintext_modulus_bits = 17;
        let input_domain = 2;
        let max_num_clients = 100;
        let num_packing = 2;
        let num_public_polynomials = 1;
        let rns_config = make_kahe_rns_config(plaintext_modulus_bits)?;
        let kahe_config = ShellKaheConfig::new(
            input_domain,
            max_num_clients,
            num_packing,
            num_public_polynomials,
            rns_config.clone(),
        )?;
        let public_seed = SingleThreadHkdfPrng::generate_seed()?;
        let kahe = ShellKahe::new(kahe_config, &public_seed)?;
        let seed = SingleThreadHkdfPrng::generate_seed()?;
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;

        // Create a key and write it to a buffer.
        let sk = kahe.key_gen(&mut prng)?;
        let sk_buffer = kahe.try_secret_key_into(sk)?;

        // Check that read+write is identity.
        let sk_recovered = kahe.try_secret_key_from(sk_buffer.clone())?;
        let sk_recovered_buffer = kahe.try_secret_key_into(sk_recovered)?;
        assert_eq!(sk_recovered_buffer, sk_buffer);

        // Generating twice the same key gives the same buffer.
        let mut prng2 = SingleThreadHkdfPrng::create(&seed)?;
        let sk2 = kahe.key_gen(&mut prng2)?;
        let sk_buffer_2 = kahe.try_secret_key_into(sk2)?;
        assert_eq!(sk_buffer, sk_buffer_2);

        // Check that each discrete Gaussian sample is within the right tail bound
        for v in sk_buffer.iter() {
            assert!(*v <= TAIL_BOUND);
            assert!(*v >= -TAIL_BOUND);
        }

        // Check a Gaussian concentration bound too.
        let mut sum = 0;
        for v in sk_buffer.iter() {
            sum += *v;
        }
        let n = sk_buffer.len() as f64;
        let mean = (sum as f64) / n as f64;
        let mean_std = SECRET_KEY_STD / n.sqrt();
        verify_le!(mean.abs(), TAIL_BOUND_MULTIPLIER * mean_std)
    }

    #[gtest]
    fn test_key_serialization_is_homomorphic() -> googletest::Result<()> {
        // Set up a ShellKahe instance.
        let plaintext_modulus_bits = 39;
        let input_domain = 10;
        let max_num_clients = 100;
        let num_packing = 2;
        let num_public_polynomials = 1;
        let rns_config = make_kahe_rns_config(plaintext_modulus_bits)?;
        let kahe_config = ShellKaheConfig::new(
            input_domain,
            max_num_clients,
            num_packing,
            num_public_polynomials,
            rns_config.clone(),
        )?;
        let public_seed = SingleThreadHkdfPrng::generate_seed()?;
        let kahe = ShellKahe::new(kahe_config, &public_seed)?;

        let pt = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let seed = SingleThreadHkdfPrng::generate_seed()?;

        // Generate two keys, write them to buffers then add the buffers together.
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let sk1 = kahe.key_gen(&mut prng)?;
        let sk2 = kahe.key_gen(&mut prng)?;
        let sk1_buffer = kahe.try_secret_key_into(sk1)?;
        let mut sk2_buffer = kahe.try_secret_key_into(sk2)?;
        for i in 0..sk1_buffer.len() {
            sk2_buffer[i] += sk1_buffer[i];
        }

        // Generate same two keys but add them together before writing to a buffer.
        let mut prng = SingleThreadHkdfPrng::create(&seed)?;
        let sk1 = kahe.key_gen(&mut prng)?;
        let mut sk2 = kahe.key_gen(&mut prng)?;
        kahe.add_keys_in_place(&sk1, &mut sk2)?;
        let sk_buffer = kahe.try_secret_key_into(sk2)?;

        // Check that the two buffers are the same.
        verify_eq!(sk_buffer[..], sk2_buffer[..])
    }
}
