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

/// Base trait all roles (Client, Server, Decryptor, Verifier) inherit from.
/// Defines messages and constants shared between all roles.
pub trait SecureAggregationCommon {
    /// The public key share received by the Server from the Decryptor.
    type DecryptorPublicKeyShare;
    /// The public key sent from the Server to the client.
    type DecryptorPublicKey;
    /// The message sent by the client.
    type ClientMessage;
    /// The material from the client that the verifier must check.
    type DecryptionRequestContribution;
    /// The part of the client message that the verifier needn't check
    type CiphertextContribution;
    /// The message sent by the Server to the Decryptor to request partial
    /// decryption.
    type PartialDecryptionRequest;
    /// The partial decryption received by the Server from the Decryptor.
    type PartialDecryptionResponse;
}
