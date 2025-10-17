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

use client_traits::SecureAggregationClient;
use decryptor_traits::SecureAggregationDecryptor;
use googletest::{gtest, verify_eq, verify_that};
use kahe_shell::ShellKahe;
use parameters_shell::create_shell_configs;
use prng_traits::SecurePrng;
use server_traits::SecureAggregationServer;
use single_thread_hkdf::SingleThreadHkdfPrng;
use status::StatusErrorCode;
use status_matchers_rs::status_is;
use testing_utils::{create_willow_common, generate_random_unsigned_vector};
use vahe_shell::ShellVahe;
use verifier_traits::SecureAggregationVerifier;
use willow_v1_client::WillowV1Client;
use willow_v1_common::WillowCommon;
use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};
use willow_v1_server::{ServerState, WillowV1Server};
use willow_v1_verifier::{VerifierState, WillowV1Verifier};

/// Encrypt and decrypt with a single decryptor and single client.
#[gtest]
fn encrypt_decrypt_one() -> googletest::Result<()> {
    let public_kahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let public_ahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();

    // Create client.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
    let mut client = WillowV1Client { common, prng };

    // Create decryptor, which needs its own `common` (with same public polynomials
    // generated from the seeds) and `prng`.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
    let mut decryptor_state = DecryptorState::new();
    let mut decryptor = WillowV1Decryptor { common, prng };

    // Create server.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let server = WillowV1Server { common };
    let mut server_state = ServerState::new();

    // Create verifier.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let verifier = WillowV1Verifier { common };
    let mut verifier_state = VerifierState::new();

    // Decryptor generates public key share.
    let public_key_share = decryptor.create_public_key_share(&mut decryptor_state).unwrap();

    // Server handles the public key share.
    server.handle_decryptor_public_key_share(public_key_share, &mut server_state).unwrap();

    // Server creates the public key.
    let public_key = server.create_decryptor_public_key(&server_state).unwrap();

    // Client encrypts.
    let client_plaintext = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
    let client_message = client.create_client_message(&client_plaintext, &public_key).unwrap();

    // The client message is split and handled by the server and verifier.
    let (ciphertext_contribution, decryption_request_contribution) =
        server.split_client_message(client_message).unwrap();
    verifier.verify_and_include(decryption_request_contribution, &mut verifier_state).unwrap();
    server.handle_ciphertext_contribution(ciphertext_contribution, &mut server_state).unwrap();

    // Verifier creates the partial decryption request.
    let pd_ct = verifier.create_partial_decryption_request(verifier_state).unwrap();

    // Decryptor creates partial decryption.
    let pd = decryptor.handle_partial_decryption_request(pd_ct, &decryptor_state).unwrap();

    // Server handles the partial decryption.
    server.handle_partial_decryption(pd, &mut server_state).unwrap();

    // Server recovers the aggregation result.
    let aggregation_result = server.recover_aggregation_result(&server_state).unwrap();

    // Check that the (padded) result matches the client plaintext.
    verify_eq!(aggregation_result[..client_plaintext.len()], client_plaintext)
}

// Encrypt and decrypt with multiple clients and a single decryptor.
#[gtest]
fn encrypt_decrypt_multiple_clients() -> googletest::Result<()> {
    let public_kahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let public_ahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();

    // Create clients.
    let mut clients = vec![];
    for _ in 0..10 {
        let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
        let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
        let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
        let client = WillowV1Client { common, prng };
        clients.push(client);
    }

    // Create decryptor, which needs its own `common` (with same public polynomials
    // generated from the seeds) and `prng`.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
    let mut decryptor_state = DecryptorState::new();
    let mut decryptor = WillowV1Decryptor { common, prng };

    // Create server.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let server = WillowV1Server { common };
    let mut server_state = ServerState::new();

    // Create verifier.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let verifier = WillowV1Verifier { common };
    let mut verifier_state = VerifierState::new();

    // Decryptor generates public key share.
    let public_key_share = decryptor.create_public_key_share(&mut decryptor_state).unwrap();

    // Server handles the public key share.
    server.handle_decryptor_public_key_share(public_key_share, &mut server_state).unwrap();

    // Server creates the public key.
    let public_key = server.create_decryptor_public_key(&server_state).unwrap();

    // Clients encrypt.
    let mut expected_output = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for client in &mut clients {
        let client_plaintext = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
        for i in 0..expected_output.len() {
            expected_output[i] += client_plaintext[i];
        }
        let client_message = client.create_client_message(&client_plaintext, &public_key).unwrap();
        // The client message is split and handled by the server and verifier.
        let (ciphertext_contribution, decryption_request_contribution) =
            server.split_client_message(client_message).unwrap();
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state).unwrap();
        server.handle_ciphertext_contribution(ciphertext_contribution, &mut server_state).unwrap();
    }

    // Verifier creates the partial decryption request.
    let pd_ct = verifier.create_partial_decryption_request(verifier_state).unwrap();

    // Decryptor creates partial decryption.
    let pd = decryptor.handle_partial_decryption_request(pd_ct, &decryptor_state).unwrap();

    // Server handles the partial decryption.
    server.handle_partial_decryption(pd, &mut server_state).unwrap();

    // Server recovers the aggregation result.
    let aggregation_result = server.recover_aggregation_result(&server_state).unwrap();

    // Check that the (padded) result matches the client plaintext.
    verify_eq!(aggregation_result[..expected_output.len()], expected_output)
}

// Encrypt and decrypt with multiple clients including invalid client proofs and a single decryptor.
#[gtest]
fn encrypt_decrypt_multiple_clients_including_invalid_proofs() -> googletest::Result<()> {
    let public_kahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let public_ahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();

    // Create clients.
    let mut good_clients = vec![];
    for _ in 0..10 {
        let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
        let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
        let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
        let client = WillowV1Client { common, prng };
        good_clients.push(client);
    }

    // Create bad clients.
    let mut bad_clients = vec![];
    for _ in 0..5 {
        let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
        let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
        let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
        let client = WillowV1Client { common, prng };
        bad_clients.push(client);
    }

    // Create decryptor, which needs its own `common` (with same public polynomials
    // generated from the seeds) and `prng`.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
    let mut decryptor_state = DecryptorState::new();
    let mut decryptor = WillowV1Decryptor { common, prng };

    // Create server.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let server = WillowV1Server { common };
    let mut server_state = ServerState::new();

    // Create verifier.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let verifier = WillowV1Verifier { common };
    let mut verifier_state = VerifierState::new();

    // Decryptor generates public key share.
    let public_key_share = decryptor.create_public_key_share(&mut decryptor_state).unwrap();

    // Server handles the public key share.
    server.handle_decryptor_public_key_share(public_key_share, &mut server_state).unwrap();

    // Server creates the public key.
    let public_key = server.create_decryptor_public_key(&server_state).unwrap();

    // Good Clients encrypt and should be included in the aggregation.
    let mut expected_output = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for client in &mut good_clients {
        let client_plaintext = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
        for i in 0..expected_output.len() {
            expected_output[i] += client_plaintext[i];
        }
        let client_message = client.create_client_message(&client_plaintext, &public_key).unwrap();
        // The client message is split and handled by the server and verifier.
        let (ciphertext_contribution, decryption_request_contribution) =
            server.split_client_message(client_message).unwrap();
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state).unwrap();
        server.handle_ciphertext_contribution(ciphertext_contribution, &mut server_state).unwrap();
    }

    // Use first bad client to create a proof object that the others will use.
    let bad_proof;
    {
        let client = &mut bad_clients[0];
        let client_plaintext = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
        let client_message = client.create_client_message(&client_plaintext, &public_key).unwrap();
        bad_proof = client_message.proof;
    }
    // Bad Clients encrypt and should not be included in the aggregation.
    for i in 1..bad_clients.len() {
        let client = &mut bad_clients[i];
        let client_plaintext = vec![8, 7, 6, 5, 4, 3, 2, 1, 2, 3, 4, 5, 6, 7, 8];
        let mut client_message =
            client.create_client_message(&client_plaintext, &public_key).unwrap();
        client_message.proof = bad_proof.clone();
        // The client message is split and handled by the server and verifier.
        let (_ciphertext_contribution, decryption_request_contribution) =
            server.split_client_message(client_message).unwrap();
        verify_that!(
            verifier.verify_and_include(decryption_request_contribution, &mut verifier_state),
            status_is(StatusErrorCode::PermissionDenied)
        )?;
    }

    // Verifier creates the partial decryption request.
    let pd_ct = verifier.create_partial_decryption_request(verifier_state).unwrap();

    // Decryptor creates partial decryption.
    let pd = decryptor.handle_partial_decryption_request(pd_ct, &decryptor_state).unwrap();

    // Server handles the partial decryption.
    server.handle_partial_decryption(pd, &mut server_state).unwrap();

    // Server recovers the aggregation result.
    let aggregation_result = server.recover_aggregation_result(&server_state).unwrap();

    // Check that the (padded) result matches the client plaintext.
    verify_eq!(aggregation_result[..expected_output.len()], expected_output)
}

/// Encrypt and decrypt with multiple clients and multiple decryptors.
/// Note: This test uses RLWE parameters for production use.
#[gtest]
fn encrypt_decrypt_many_clients_decryptors() -> googletest::Result<()> {
    const INPUT_LENGTH: u64 = 100_000; // 100K
    const INPUT_DOMAIN: u64 = 1u64 << 32;
    const MAX_NUM_CLIENTS: usize = 10_000_000; // used to generate parameters.
    const MAX_NUM_DECRYPTORS: usize = 100; // used to generate parameters.
    const NUM_CLIENTS: usize = 3; // Actual number of clients to create.
    const NUM_DECRYPTORS: usize = 3; // Actual number of decryptors to create.

    // Create the public seeds for all clients, decryptors, and server.
    let public_kahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let public_ahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();

    // Create server.
    let (kahe_config, ahe_config) =
        create_shell_configs(INPUT_LENGTH, INPUT_DOMAIN, MAX_NUM_CLIENTS, MAX_NUM_DECRYPTORS)
            .unwrap();
    let kahe = ShellKahe::new(kahe_config, &public_kahe_seed).unwrap();
    let vahe = ShellVahe::new(ahe_config, &public_ahe_seed).unwrap();
    let common = WillowCommon { kahe, vahe };
    let server = WillowV1Server { common };
    let mut server_state = ServerState::new();

    // Create verifier.
    let (kahe_config, ahe_config) =
        create_shell_configs(INPUT_LENGTH, INPUT_DOMAIN, MAX_NUM_CLIENTS, MAX_NUM_DECRYPTORS)
            .unwrap();
    let kahe = ShellKahe::new(kahe_config, &public_kahe_seed).unwrap();
    let vahe = ShellVahe::new(ahe_config, &public_ahe_seed).unwrap();
    let common = WillowCommon { kahe, vahe };
    let verifier = WillowV1Verifier { common };
    let mut verifier_state = VerifierState::new();

    // Create decryptors, which needs their own `common` (with same public
    // polynomials generated from the seeds) and `prng`.
    let mut decryptors = vec![];
    let mut decryptor_states = vec![];
    for _ in 0..NUM_DECRYPTORS {
        let (kahe_config, ahe_config) =
            create_shell_configs(INPUT_LENGTH, INPUT_DOMAIN, MAX_NUM_CLIENTS, MAX_NUM_DECRYPTORS)
                .unwrap();
        let kahe = ShellKahe::new(kahe_config, &public_kahe_seed).unwrap();
        let vahe = ShellVahe::new(ahe_config, &public_ahe_seed).unwrap();
        let common = WillowCommon { kahe, vahe };
        let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
        let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
        let mut decryptor_state = DecryptorState::new();
        let mut decryptor = WillowV1Decryptor { common, prng };

        // Decryptor generates public key share.
        let public_key_share = decryptor.create_public_key_share(&mut decryptor_state).unwrap();

        // Server handles the public key share.
        server.handle_decryptor_public_key_share(public_key_share, &mut server_state).unwrap();

        decryptors.push(decryptor);
        decryptor_states.push(decryptor_state);
    }

    // Server creates the public key.
    let public_key = server.create_decryptor_public_key(&server_state).unwrap();

    // Create clients, and each client generates their messages.
    let mut expected_output = vec![0; INPUT_LENGTH as usize];
    for _ in 0..NUM_CLIENTS {
        let (kahe_config, ahe_config) =
            create_shell_configs(INPUT_LENGTH, INPUT_DOMAIN, MAX_NUM_CLIENTS, MAX_NUM_DECRYPTORS)
                .unwrap();
        let kahe = ShellKahe::new(kahe_config, &public_kahe_seed).unwrap();
        let vahe = ShellVahe::new(ahe_config, &public_ahe_seed).unwrap();
        let common = WillowCommon { kahe, vahe };
        let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
        let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
        let mut client = WillowV1Client { common, prng };

        let client_plaintext = generate_random_unsigned_vector(INPUT_LENGTH as usize, INPUT_DOMAIN);
        for i in 0..expected_output.len() {
            expected_output[i] += client_plaintext[i];
        }
        let client_message = client.create_client_message(&client_plaintext, &public_key).unwrap();
        // The client message is split and handled by the server and verifier.
        let (ciphertext_contribution, decryption_request_contribution) =
            server.split_client_message(client_message).unwrap();
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state).unwrap();
        server.handle_ciphertext_contribution(ciphertext_contribution, &mut server_state).unwrap();
    }

    // Verifier creates the partial decryption request.
    let pd_ct = verifier.create_partial_decryption_request(verifier_state).unwrap();

    // Decryptors perform partial decryption.
    for i in 0..NUM_DECRYPTORS {
        // Each decryptor creates partial decryption.
        let pd = decryptors[i]
            .handle_partial_decryption_request(pd_ct.clone(), &decryptor_states[i])
            .unwrap();

        // Server handles the partial decryption.
        server.handle_partial_decryption(pd, &mut server_state).unwrap();
    }

    // Server recovers the aggregation result.
    let aggregation_result = server.recover_aggregation_result(&server_state).unwrap();

    // Check that the (padded) result matches the client plaintext.
    verify_eq!(aggregation_result[..expected_output.len()], expected_output)
}

// Encrypt and decrypt with multiple clients and multiple decryptors, but no dropout.
#[gtest]
fn encrypt_decrypt_no_dropout() -> googletest::Result<()> {
    let public_kahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let public_ahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();

    // Create clients.
    let mut clients = vec![];
    for _ in 0..10 {
        let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
        let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
        let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
        let client = WillowV1Client { common, prng };
        clients.push(client);
    }

    // Create decryptors, which need their own `common` (with same public polynomials
    // generated from the seeds) and `prng`.
    let mut decryptor_states = vec![];
    let mut decryptors = vec![];
    for _ in 0..10 {
        let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
        let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
        let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
        let decryptor_state = DecryptorState::new();
        let decryptor = WillowV1Decryptor { common, prng };
        decryptor_states.push(decryptor_state);
        decryptors.push(decryptor);
    }

    // Create server.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let server = WillowV1Server { common };
    let mut server_state = ServerState::new();

    // Create verifier.
    let common = create_willow_common(&public_kahe_seed, &public_ahe_seed);
    let verifier = WillowV1Verifier { common };
    let mut verifier_state = VerifierState::new();

    // Decryptors generate public key shares.
    for i in 0..decryptors.len() {
        let public_key_share =
            decryptors[i].create_public_key_share(&mut decryptor_states[i]).unwrap();
        // Server handles the public key share.
        server.handle_decryptor_public_key_share(public_key_share, &mut server_state).unwrap();
    }

    // Server creates the public key.
    let public_key = server.create_decryptor_public_key(&server_state).unwrap();

    // Clients encrypt.
    let mut expected_output = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for client in &mut clients {
        let client_plaintext = vec![1, 2, 3, 4, 5, 6, 7, 8, 7, 6, 5, 4, 3, 2, 1];
        for i in 0..expected_output.len() {
            expected_output[i] += client_plaintext[i];
        }
        let client_message = client.create_client_message(&client_plaintext, &public_key).unwrap();
        // The client message is split and handled by the server and verifier.
        let (ciphertext_contribution, decryption_request_contribution) =
            server.split_client_message(client_message).unwrap();
        verifier.verify_and_include(decryption_request_contribution, &mut verifier_state).unwrap();
        server.handle_ciphertext_contribution(ciphertext_contribution, &mut server_state).unwrap();
    }

    // Verifier creates the partial decryption request.
    let pd_ct = verifier.create_partial_decryption_request(verifier_state).unwrap();

    // Decryptors perform partial decryption.
    for i in 0..decryptors.len() {
        let pd = decryptors[i]
            .handle_partial_decryption_request(pd_ct.clone(), &decryptor_states[i])
            .unwrap();
        // Server handles the partial decryption.
        server.handle_partial_decryption(pd, &mut server_state).unwrap();
    }

    // Server recovers the aggregation result.
    let aggregation_result = server.recover_aggregation_result(&server_state).unwrap();

    // Check that the (padded) result matches the client plaintext.
    verify_eq!(aggregation_result[..expected_output.len()], expected_output)
}
