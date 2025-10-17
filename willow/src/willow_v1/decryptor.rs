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

use ahe_traits::{AheBase, AheKeygen, PartialDec};
use decryptor_traits::SecureAggregationDecryptor;
use kahe_traits::KaheBase;
use vahe_traits::{EncryptVerify, VaheBase};
use willow_v1_common::{
    DecryptorPublicKeyShare, PartialDecryptionRequest, PartialDecryptionResponse, WillowCommon,
};

/// Lightweight decryptor directly exposing KAHE/VAHE types. It verifies only the client proofs,
/// does not provide verifiable partial decryptions.
pub struct WillowV1Decryptor<Kahe, Vahe: VaheBase> {
    pub common: WillowCommon<Kahe, Vahe>,
    pub prng: Vahe::Rng,
}

pub struct DecryptorState<Vahe: VaheBase> {
    sk_share: Option<Vahe::SecretKeyShare>,
}

impl<Vahe: VaheBase> DecryptorState<Vahe> {
    pub fn new() -> Self {
        Self { sk_share: None }
    }
}


/// Implementation of the `SecureAggregationDecryptor` trait for the generic
/// KAHE/AHE decryptor, using WillowCommon as the common types (e.g. protocol
/// messages are directly the AHE public key and ciphertexts).
impl<Kahe, Vahe> SecureAggregationDecryptor<WillowCommon<Kahe, Vahe>>
    for WillowV1Decryptor<Kahe, Vahe>
where
    Vahe: VaheBase + EncryptVerify + PartialDec + AheKeygen,
    Kahe: KaheBase,
{
    type DecryptorState = DecryptorState<Vahe>;

    /// Creates a public key share to be sent to the Server, updating the
    /// decryptor state.
    fn create_public_key_share(
        &mut self,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<DecryptorPublicKeyShare<Vahe>, status::StatusError> {
        let (sk_share, pk_share, _) = self.common.vahe.key_gen(&mut self.prng)?;
        decryptor_state.sk_share = Some(sk_share);
        Ok(pk_share)
    }

    /// Handles a partial decryption request received from the Server. Returns a
    /// partial decryption to the Server.
    fn handle_partial_decryption_request(
        &mut self,
        partial_decryption_request: PartialDecryptionRequest<Vahe>,
        decryptor_state: &Self::DecryptorState,
    ) -> Result<PartialDecryptionResponse<Vahe>, status::StatusError> {
        let Some(ref sk_share) = decryptor_state.sk_share else {
            return Err(status::failed_precondition(
                "decryptor_state does not contain a secret key share".to_string(),
            ));
        };
        // Compute the partial decryption.
        let pd = self.common.vahe.partial_decrypt(
            &partial_decryption_request.partial_dec_ciphertext,
            sk_share,
            &mut self.prng,
        )?;
        Ok(PartialDecryptionResponse { partial_decryption: pd })
    }
}
