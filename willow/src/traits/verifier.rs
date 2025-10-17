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
/// Base trait for the secure aggregation verifier.
///
/// Protocol diagram: https://drive.google.com/file/d/10wz5fkzhliVSqcs-rZtn9t7YDXCl5tf8/view?usp=sharing
pub trait SecureAggregationVerifier<Common: common_traits::SecureAggregationCommon> {
    /// The state held by the verifier between messages.
    type VerifierState;

    /// Verifies a clients decryption request contribution.
    fn verify_and_include(
        &self,
        contribution: Common::DecryptionRequestContribution,
        state: &mut Self::VerifierState,
    ) -> Result<(), StatusError>;

    /// Returns a decryption request for the sum of the contributions, consumes the state.
    fn create_partial_decryption_request(
        &self,
        state: Self::VerifierState,
    ) -> Result<Common::PartialDecryptionRequest, StatusError>;
}
