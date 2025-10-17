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

use googletest::{
    expect_that, fail, gtest,
    matchers::{container_eq, eq},
    Result,
};
use kahe::{create_public_parameters, decrypt, encrypt, generate_secret_key};
use rand::Rng;
use status::StatusErrorCode;
use status_matchers_rs::status_is;

// RNS configuration. LOG_T is the bit length of the KAHE plaintext modulus.
const LOG_T: u64 = 11;
const LOG_N: u64 = 12;
const QS: [u64; 2] = [1125899906826241, 1125899906629633];

#[gtest]
fn encrypt_decrypt() -> Result<()> {
    // Generate public parameters.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let num_public_polynomials = 1;
    let params = create_public_parameters(LOG_N, LOG_T, &QS, num_public_polynomials, &public_seed)?;

    // Generate secret key.
    let seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&seed)?;
    let secret_key = generate_secret_key(&params, &mut prng)?;

    // Encrypt small vector. `ciphertext` is a wrapper around a C++ pointer.
    let input_domain = 10;
    let num_packing = 2;
    let input_values = vec![1, 2, 3];
    let ciphertext =
        encrypt(&input_values, &secret_key, &params, input_domain, num_packing, &mut prng)?;

    // Allocate a small buffer, and decrypt into it.
    let output_values_length = 3;
    let mut output_values = vec![0; output_values_length];
    let n_written =
        decrypt(&ciphertext, &secret_key, &params, input_domain, num_packing, &mut output_values)?;

    expect_that!(n_written, eq(3));
    expect_that!(output_values, container_eq(input_values));

    Ok(())
}

#[gtest]
fn encrypt_decrypt_padding() -> Result<()> {
    // Generate public parameters and secret key.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let num_public_polynomials = 1;
    let params = create_public_parameters(LOG_N, LOG_T, &QS, num_public_polynomials, &public_seed)?;
    let seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&seed)?;
    let secret_key = generate_secret_key(&params, &mut prng)?;

    // Generate a short random vector, encrypt and decrypt it.
    let num_messages = 40;
    let input_domain = 10;
    let num_packing = 2;
    let mut input_values: Vec<u64> = Vec::with_capacity(num_messages);
    for _ in 0..num_messages {
        input_values.push(rand::thread_rng().gen_range(0..input_domain));
    }
    let ciphertext =
        encrypt(&input_values, &secret_key, &params, input_domain, num_packing, &mut prng)?;

    // Number of values packed into one polynomial.
    let padded_length = ((1 << LOG_N) * num_packing) as usize;

    // Allocate more than enough space.
    let output_values_length = padded_length * 2;
    let mut output_values = vec![42; output_values_length];

    // Decrypt into the buffer. The rest should be unused.
    let n_written =
        decrypt(&ciphertext, &secret_key, &params, input_domain, num_packing, &mut output_values)?;

    // Check that message is correctly decrypted with right padding.
    expect_that!(n_written, eq(padded_length));
    expect_that!(output_values[..num_messages], container_eq(input_values));
    expect_that!(
        output_values[num_messages..padded_length],
        container_eq(vec![0; padded_length - num_messages])
    );
    expect_that!(
        output_values[padded_length..output_values_length],
        container_eq(vec![42; output_values_length - padded_length])
    );

    Ok(())
}

#[gtest]
fn encrypt_decrypt_long() -> Result<()> {
    // Generate public parameters and secret key.
    let public_seed = single_thread_hkdf::generate_seed()?;
    let num_public_polynomials = 10; // Generate enough a's to pass long messages.
    let params = create_public_parameters(LOG_N, LOG_T, &QS, num_public_polynomials, &public_seed)?;
    let seed = single_thread_hkdf::generate_seed()?;
    let mut prng = single_thread_hkdf::create(&seed)?;
    let secret_key = generate_secret_key(&params, &mut prng)?;
    let num_packing = 8;

    // Number of values packed into one polynomial.
    let poly_capacity = ((1 << LOG_N) * num_packing) as usize;

    // Generate a long random vector, encrypt and decrypt it.
    let input_domain = 2;
    let num_messages = 3 * poly_capacity + 1;

    let mut input_values: Vec<u64> = Vec::with_capacity(num_messages);
    for _ in 0..num_messages {
        input_values.push(rand::thread_rng().gen_range(0..input_domain));
    }
    let ciphertext =
        encrypt(&input_values, &secret_key, &params, input_domain, num_packing, &mut prng)?;

    // Allocate more than enough space.
    let output_values_length = num_messages * 2;
    let mut output_values = vec![42; output_values_length];

    // Decrypt into the buffer. The rest should be unused.
    let n_written =
        decrypt(&ciphertext, &secret_key, &params, input_domain, num_packing, &mut output_values)?;

    // Check that message is correctly decrypted with right padding.
    let padded_length = 4 * poly_capacity; // Last polynomial is padded.
    expect_that!(n_written, eq(padded_length));
    expect_that!(output_values[..num_messages], container_eq(input_values));
    expect_that!(
        output_values[num_messages..padded_length],
        container_eq(vec![0; padded_length - num_messages])
    );
    expect_that!(
        output_values[padded_length..output_values_length],
        container_eq(vec![42; output_values_length - padded_length])
    );

    // If the input is too long, we should fail.
    let num_messages = num_public_polynomials * poly_capacity + 1;
    let mut input_values: Vec<u64> = Vec::with_capacity(num_messages);
    for _ in 0..num_messages {
        input_values.push(rand::thread_rng().gen_range(0..input_domain));
    }
    match encrypt(&input_values, &secret_key, &params, input_domain, num_packing, &mut prng) {
        Err(e) => expect_that!(e, status_is(StatusErrorCode::InvalidArgument)),
        Ok(_) => fail!("Expected call to fail")?,
    }

    Ok(())
}
