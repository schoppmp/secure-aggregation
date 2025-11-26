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

use protobuf::prelude::*;
use willow_api_common::AggregationConfig;
use willow_api_common_rust_proto::AggregationConfigProto;
use willow_api_common_rust_proto::VectorConfig;

pub fn aggregation_config_from_proto(
    aggregation_config_proto: &AggregationConfigProto,
) -> AggregationConfig {
    AggregationConfig {
        vector_lengths_and_bounds: aggregation_config_proto
            .vector_configs()
            .iter()
            .map(|(key, value)| (key.to_string(), (value.length() as isize, value.bound())))
            .collect(),
        max_number_of_decryptors: aggregation_config_proto.max_number_of_decryptors(),
        max_decryptor_dropouts: aggregation_config_proto.max_decryptor_dropouts(),
        max_number_of_clients: aggregation_config_proto.max_number_of_clients(),
        session_id: aggregation_config_proto.session_id().to_string(),
    }
}

pub fn aggregation_config_to_proto(
    aggregation_config: &AggregationConfig,
) -> AggregationConfigProto {
    let mut aggregation_config_proto = proto!(AggregationConfigProto {
        vector_configs: protobuf::Map::default(),
        max_number_of_decryptors: aggregation_config.max_number_of_decryptors,
        max_decryptor_dropouts: aggregation_config.max_decryptor_dropouts,
        max_number_of_clients: aggregation_config.max_number_of_clients,
        session_id: aggregation_config.session_id.clone(),
    });
    aggregation_config_proto.vector_configs_mut().copy_from(
        aggregation_config.vector_lengths_and_bounds.iter().map(|(key, (length, bound))| {
            (key.as_str(), proto!(VectorConfig { length: *length as i64, bound: *bound }))
        }),
    );
    aggregation_config_proto
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::{gtest, matchers::eq, verify_that};
    use testing_utils::generate_aggregation_config;

    #[gtest]
    fn convert_to_and_from_proto() -> googletest::Result<()> {
        let aggregation_config = generate_aggregation_config("default".to_string(), 16, 10, 1, 1);

        verify_that!(
            aggregation_config_from_proto(&aggregation_config_to_proto(&aggregation_config)),
            eq(&aggregation_config),
        )
    }
}
