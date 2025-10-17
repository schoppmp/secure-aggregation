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

use ahe_shell::ShellAheConfig;
use kahe_shell::{KaheRnsConfig, ShellKaheConfig};

/// Creates an KAHE RNS configuration with the given plaintext modulus bits, by
/// looking up some pre-generated configurations.
pub fn make_kahe_rns_config(
    plaintext_modulus_bits: usize,
) -> Result<KaheRnsConfig, status::StatusError> {
    // Configurations below come from:
    // google3/experimental/users/baiyuli/async_rlwe_secagg/parameters.cc,
    // originally generated with:
    // google3/experimental/users/baiyuli/lattice/find_rns_moduli.sage
    // NOTE: For decoding we need  t * e in [-q/2, q/2).
    //       We take plaintext_modulus_bits < composite_modulus_bits - 1 -
    //       log2(kTailBoundMultiplier) - log2(kPrgErrorS)
    //       = composite_modulus_bits - 7
    match plaintext_modulus_bits {
        17 => Ok(KaheRnsConfig { log_n: 10, log_t: 17, qs: vec![16760833] }),
        39 => Ok(KaheRnsConfig { log_n: 11, log_t: 39, qs: vec![70368744067073] }),
        93 => {
            Ok(KaheRnsConfig { log_n: 12, log_t: 93, qs: vec![1125899906826241, 1125899906629633] })
        }
        _ => Err(status::invalid_argument(format!(
            "No RNS configuration for plaintext_modulus_bits = {}",
            plaintext_modulus_bits
        ))),
    }
}

/// Creates a sample KAHE configuration, for quick tests that need just any
/// valid configuration.
pub fn make_kahe_config() -> ShellKaheConfig {
    const PLAINTEXT_MODULUS_BITS: usize = 93;
    const INPUT_DOMAIN: u64 = 10;
    const MAX_NUM_CLIENTS: usize = 100_000;
    const NUM_PACKING: usize = 2;
    const NUM_PUBLIC_POLYNOMIALS: usize = 1;

    let rns_config = make_kahe_rns_config(PLAINTEXT_MODULUS_BITS).unwrap();
    ShellKaheConfig::new(
        INPUT_DOMAIN,
        MAX_NUM_CLIENTS,
        NUM_PACKING,
        NUM_PUBLIC_POLYNOMIALS,
        rns_config,
    )
    .unwrap()
}

/// Creates an AHE configuration with 69-bit main modulus and 64-bit RNS moduli.
/// Parameters from https://github.com/google/shell-encryption/blob/master/shell_encryption/testing/parameters.h
pub fn make_ahe_config() -> ShellAheConfig {
    // Defines RLWE parameters for the ring Z[X]/(Q, X^N+1) where N = 2^log_n,
    // and Q = prod(qs). This is the ciphertext space of the AHE scheme, i.e.
    // the public keys and ciphertexts are all polynomials in this ring.
    // The primes in `qs` must be NTT-friendly for X^{2N} + 1, i.e. each member
    // q of `qs` should be such that 4N factors q-1. This allows to compute the
    // "wrap around" polynomials of the public key shares.
    // The parameter `t` specifies the plaintext modulus, i.e. the plaintext of
    // the AHE scheme is Z[X]/(t, X^N+1).
    // The parameter `s_flood` specifies the Gaussian parameter of the flooding
    // noise polynomial e(X) used in partial decryptions, i.e. e(X) has i.i.d.
    // discrete Gaussian coefficients of parameter `s_flood`.
    //
    ShellAheConfig { log_n: 12, t: 54001, qs: vec![34359410689, 34359361537], s_flood: 4.25839e+13 }
}
