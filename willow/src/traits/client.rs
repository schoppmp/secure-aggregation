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

use common_traits::SecureAggregationCommon;
use status::StatusError;

/// Base trait for the secure aggregation Client.
pub trait SecureAggregationClient<Common: SecureAggregationCommon> {
    /// The plaintext to be aggregated.
    type Plaintext;

    /// Creates a client message to be sent to the Server.
    fn create_client_message(
        &mut self,
        plaintext: &Self::Plaintext,
        signed_public_key: &Common::DecryptorPublicKey,
    ) -> Result<Common::ClientMessage, StatusError>;
}
