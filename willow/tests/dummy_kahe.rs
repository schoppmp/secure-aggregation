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

use kahe_traits::{KaheBase, KaheDecrypt, KaheEncrypt, KaheKeygen};
use std::ops::AddAssign;

/// A placeholder type for keys, plaintexts and ciphertexts.
#[derive(Default, Debug, PartialEq)]
pub struct Poly(Vec<u8>); // Wrapper around Vec to implement our own AddAssign.

/// Add two polynomials coordinate-wise.
impl AddAssign<&Self> for Poly {
    fn add_assign(&mut self, rhs: &Self) {
        for (i, v) in rhs.0.iter().enumerate() {
            self.0[i] += v;
        }
    }
}

/// Base type holding data shared by all Dummy KAHE roles.
#[derive(Default)]
pub struct DummyKahe {
    a: Poly, // public *a*, same for all roles.
}

impl DummyKahe {
    /// Setup function that samples *a* from a seed.
    pub fn setup(seed: &[u8; 32]) -> Self {
        let a = Poly(vec![seed[0]]); // Could be a PRG
        DummyKahe { a }
    }
}

/// Associated types for DummyKahe.
impl KaheBase for DummyKahe {
    type SecretKey = Poly;
    type Plaintext = Poly;
    type Ciphertext = Poly;
    type Rng = Vec<u8>;

    fn add_keys_in_place(&self, left: &Poly, right: &mut Poly) -> status::Status {
        *right += left;
        Ok(())
    }

    fn add_plaintexts_in_place(&self, left: &Poly, right: &mut Poly) -> status::Status {
        *right += left;
        Ok(())
    }

    fn add_ciphertexts_in_place(&self, left: &Poly, right: &mut Poly) -> status::Status {
        *right += left;
        Ok(())
    }
}

impl KaheKeygen for DummyKahe {
    fn key_gen(&self, r: &mut Self::Rng) -> Result<Self::SecretKey, status::StatusError> {
        Ok(Poly(vec![r[0]]))
    }
}

impl KaheEncrypt for DummyKahe {
    /// Encrypt as identity.
    fn encrypt(
        &self,
        plaintext: &Self::Plaintext,
        _: &Self::SecretKey,
        _: &mut Self::Rng,
    ) -> Result<Self::Ciphertext, status::StatusError> {
        let _ = &self.a.0; // We could use *a* here.
        Ok(Poly(plaintext.0.to_vec())) // Allocate a new vec with identical elements.
    }
}

impl KaheDecrypt for DummyKahe {
    /// Decrypt as identity.
    fn decrypt(
        &self,
        ciphertext: &Self::Ciphertext,
        _: &Self::SecretKey,
    ) -> Result<Self::Plaintext, status::StatusError> {
        Ok(Poly(ciphertext.0.to_vec()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use googletest::{gtest, verify_eq, verify_that};

    /// Test that sum is implemented correctly.
    #[gtest]
    fn sum() -> googletest::Result<()> {
        let mut a = Poly(vec![1, 2, 3]);
        let b = Poly(vec![4, 5, 6]);
        a += &b;
        verify_eq!(a.0, vec![5, 7, 9])
    }

    /// Check that a single input is encrypted and decrypted correctly.
    #[gtest]
    fn single_input() -> googletest::Result<()> {
        // This test maintains the state of everyone. In the binaries, some
        // functions will be called by the client and some by the server,
        // and each role will persist some state to pass the right arguments.

        // Both Client and Server would run this on their side.
        let seed = [0u8; 32];
        let dummy_kahe = DummyKahe::setup(&seed);

        // Client generates key and encrypts message.
        let mut rng = vec![0u8];
        let sk = dummy_kahe.key_gen(&mut rng)?;
        let plaintext = Poly(vec![1, 2, 3]);
        let ciphertext = dummy_kahe.encrypt(&plaintext, &sk, &mut rng)?;

        // Server receives ciphertext and decrypts.
        // (In reality there will be multiple inputs)
        let decrypted = dummy_kahe.decrypt(&ciphertext, &sk)?;
        verify_eq!(plaintext, decrypted)
    }

    /// Check homomorphic addition of two inputs.
    #[gtest]
    fn add_two_inputs() -> googletest::Result<()> {
        let seed = [0u8; 32];
        let dummy_kahe = DummyKahe::setup(&seed);

        // Client 1
        let mut rng1 = vec![0u8];
        let sk1 = dummy_kahe.key_gen(&mut rng1)?;
        let pt1 = Poly(vec![1, 2, 3]);
        let ct1 = dummy_kahe.encrypt(&pt1, &sk1, &mut rng1)?;

        // Client 2
        let mut rng2 = vec![0u8];
        let mut sk2 = dummy_kahe.key_gen(&mut rng2)?;
        let mut pt2 = Poly(vec![4, 5, 6]);
        let mut ct2 = dummy_kahe.encrypt(&pt2, &sk2, &mut rng2)?;

        // Decryptor adds up keys
        dummy_kahe.add_keys_in_place(&sk1, &mut sk2)?;

        // Server adds ciphertexts and uses aggregated key to decrypt.
        dummy_kahe.add_ciphertexts_in_place(&ct1, &mut ct2)?;
        let pt_sum = dummy_kahe.decrypt(&ct2, &sk2)?;
        dummy_kahe.add_plaintexts_in_place(&pt1, &mut pt2)?;
        verify_eq!(pt2, pt_sum)
    }
}
