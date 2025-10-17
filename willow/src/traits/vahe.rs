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

use ahe_traits::AheBase;
use status::{Status, StatusError};

pub trait VaheBase: AheBase {
    type KeyGenProof;
    type EncryptionProof: Clone;
    type PartialDecProof;
}

pub trait VerifiableKeyGen: VaheBase {
    fn verifiable_key_gen(
        &self,
        prng: &mut Self::Rng,
    ) -> Result<(Self::SecretKeyShare, Self::PublicKeyShare, Self::KeyGenProof), StatusError>;
}

pub trait KeyGenVerify: VaheBase {
    fn verify_key_gen(&self, proof: &Self::KeyGenProof, key_share: &Self::PublicKeyShare)
        -> Status;
}

pub trait VerifiableEncrypt: VaheBase {
    fn verifiable_encrypt(
        &self,
        plaintext: &Self::Plaintext,
        pk: &Self::PublicKey,
        prng: &mut Self::Rng,
    ) -> Result<(Self::Ciphertext, Self::EncryptionProof), StatusError>;
}

pub trait EncryptVerify: VaheBase {
    fn verify_encrypt(
        &self,
        proof: &Self::EncryptionProof,
        ciphertext: &Self::PartialDecCiphertext,
    ) -> Status;
}

pub trait VerifiablePartialDec: VaheBase {
    fn verifiable_partial_dec(
        &self,
        ct_1: &Self::PartialDecCiphertext,
        sk: &Self::SecretKeyShare,
        prng: &mut Self::Rng,
    ) -> Result<(Self::PartialDecryption, Self::PartialDecProof), StatusError>;
}

pub trait PartialDecVerify: VaheBase {
    fn verify_partial_dec(
        &self,
        proof: &Self::PartialDecProof,
        ct_1: &Self::PartialDecCiphertext,
        pd: &Self::PartialDecryption,
    ) -> Status;
}

pub trait Recover: VaheBase {
    /// Decrypt a ciphertext with aggregated partial decryptions. We expect the
    /// partial decryptions and ciphertexts to be already summed (e.g. to
    /// let the server accumulate as they wish).
    fn recover(
        &self,
        pd: &Self::PartialDecryption,
        ct_0: &Self::RecoverCiphertext,
        plaintex_len: Option<usize>,
    ) -> Result<Self::Plaintext, StatusError>;
}
