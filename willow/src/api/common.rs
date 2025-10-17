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

use std::collections::HashMap;

/// The configuration of the aggregation.
/// vector_lengths_and_bounds: The length and upper bound of each vector to be aggregated,
///                            indexed by the name of the vector.
/// max_number_of_decryptors:  The maximum number of decryptors that will participate in the
///                            aggregation.
/// max_decryptor_dropouts:    The maximum number decryptors that can drop out without the
///                            aggregation failing.
/// max_number_of_clients:     The maximum number of clients that will participate in the
///                            aggregation.
/// session_id:                The session id of the aggregation.
/// willow_version:            The version of the willow protocol.
#[derive(Debug, Clone)]
pub struct AggregationConfig {
    pub vector_lengths_and_bounds: HashMap<String, (isize, i64)>,
    pub max_number_of_decryptors: i64,
    pub max_decryptor_dropouts: i64,
    pub max_number_of_clients: i64,
    pub session_id: String,
    pub willow_version: (u8, u8),
}
