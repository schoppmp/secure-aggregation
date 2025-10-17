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

use status::StatusError;

/// Base trait for the Decryptor.
pub trait SecureAggregationDecryptor<Common: common_traits::SecureAggregationCommon> {
    /// The state held by the Decryptor between messages.
    type DecryptorState;

    /// Creates a public key share to be sent to the Server, updating the
    /// decryptor state.
    fn create_public_key_share(
        &mut self,
        decryptor_state: &mut Self::DecryptorState,
    ) -> Result<Common::DecryptorPublicKeyShare, StatusError>;

    /// Handles a partial decryption request received from the Server. Returns a
    /// partial decryption to the Server.
    fn handle_partial_decryption_request(
        &mut self,
        partial_decryption_request: Common::PartialDecryptionRequest,
        decryptor_state: &Self::DecryptorState,
    ) -> Result<Common::PartialDecryptionResponse, StatusError>;
}
