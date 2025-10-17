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

use clap::Parser;
use std::hint::black_box;
use std::time::Duration;

use client_traits::SecureAggregationClient;
use decryptor_traits::SecureAggregationDecryptor;
use kahe_shell::{ShellKahe, ShellKaheConfig};
use kahe_traits::KaheBase;
use prng_traits::SecurePrng;
use server_traits::SecureAggregationServer;
use shell_testing_parameters::{make_ahe_config, make_kahe_rns_config};
use single_thread_hkdf::SingleThreadHkdfPrng;
use testing_utils::{generate_random_unsigned_vector, ShellClient, ShellClientMessage};
use vahe_shell::ShellVahe;
use verifier_traits::SecureAggregationVerifier;
use willow_v1_client::WillowV1Client;
use willow_v1_common::{
    CiphertextContribution, DecryptionRequestContribution, DecryptorPublicKey,
    PartialDecryptionRequest, WillowCommon,
};
use willow_v1_decryptor::{DecryptorState, WillowV1Decryptor};
use willow_v1_server::{ServerState, WillowV1Server};
use willow_v1_verifier::{VerifierState, WillowV1Verifier};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Input length.
    #[arg(short = 'l', long, default_value_t = 100)]
    pub input_length: usize,

    /// Input domain, i.e. each client submits a vector in [0,t)^l.
    #[arg(short = 't', long, default_value_t = 10)]
    pub input_domain: u64,

    /// Max number of clients.
    #[arg(short = 'n', long, default_value_t = 1_000)]
    pub max_num_clients: usize,

    /// Number of values to pack on each coefficient.
    #[arg(short = 'L', long, default_value_t = 2)]
    pub num_packing: usize,

    /// Number of bits in the plaintext modulus.
    #[arg(long, default_value_t = 93)]
    pub plaintext_modulus_bits: usize,

    /// Number of iterations.
    #[arg(long, default_value_t = 1_000)]
    pub n_iterations: usize,

    /// Handler to benchmark.
    #[arg(long, default_value_t = String::from("decryptor_partial_decryption"))]
    pub handler: String,
}

fn bench<Inputs>(args: &Args, setup: fn(&Args) -> Inputs, run: fn(&mut Inputs) -> ()) -> Duration {
    let n_iterations = args.n_iterations;
    let mut inputs = setup(args);
    let t = std::time::Instant::now();
    for _ in 0..n_iterations {
        run(&mut inputs);
    }
    let duration = t.elapsed();
    duration / (n_iterations as u32)
}

pub fn match_and_bench(args: &Args) -> Duration {
    match args.handler.as_str() {
        "client" => bench(args, setup_client, run_client),
        "decryptor_partial_decryption" => {
            bench(args, setup_decryptor_partial_decryption, run_decryptor_partial_decryption)
        }
        "verifier_verify_client_message" => {
            bench(args, setup_verifier_verify_client_message, run_verifier_verify_client_message)
        }
        "server_handle_client_message" => {
            bench(args, setup_server_handle_client_message, run_server_handle_client_message)
        }
        "server_recover_aggregation_result" => bench(
            args,
            setup_server_recover_aggregation_result,
            run_server_recover_aggregation_result,
        ),
        _ => panic!("Unsupported handler: {}", args.handler),
    }
}

// Common inputs that are shared by all benchmarks.

struct BaseInputs {
    client: WillowV1Client<ShellKahe, ShellVahe>,
    decryptor: WillowV1Decryptor<ShellKahe, ShellVahe>,
    decryptor_state: DecryptorState<ShellVahe>,
    server: WillowV1Server<ShellKahe, ShellVahe>,
    server_state: ServerState<ShellKahe, ShellVahe>,
    verifier: WillowV1Verifier<ShellKahe, ShellVahe>,
    verifier_state: VerifierState<ShellVahe>,
    public_key: DecryptorPublicKey<ShellVahe>,
}

fn setup_base(args: &Args) -> BaseInputs {
    // Create common configs and seeds. Prepare enough public polynomials to
    // accomodate the input length.
    let kahe_rns_config = make_kahe_rns_config(args.plaintext_modulus_bits).unwrap();
    let num_coeffs = 1 << kahe_rns_config.log_n;
    let num_public_polynomials = (args.input_length as f64 / num_coeffs as f64).ceil() as usize;
    let kahe_config = ShellKaheConfig::new(
        args.input_domain,
        args.max_num_clients,
        args.num_packing,
        num_public_polynomials,
        kahe_rns_config.clone(),
    )
    .unwrap();
    let ahe_config = make_ahe_config();
    let public_kahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let public_ahe_seed = SingleThreadHkdfPrng::generate_seed().unwrap();

    // Create client.
    let common = WillowCommon {
        kahe: ShellKahe::new(kahe_config.clone(), &public_kahe_seed).unwrap(),
        vahe: ShellVahe::new(ahe_config.clone(), &public_ahe_seed).unwrap(),
    };
    let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
    let client = ShellClient { common, prng };

    // Create decryptor, which needs its own `common` and `prng`.
    let common = WillowCommon {
        kahe: ShellKahe::new(kahe_config.clone(), &public_kahe_seed).unwrap(),
        vahe: ShellVahe::new(ahe_config.clone(), &public_ahe_seed).unwrap(),
    };
    let seed = SingleThreadHkdfPrng::generate_seed().unwrap();
    let prng = SingleThreadHkdfPrng::create(&seed).unwrap();
    let mut decryptor_state = DecryptorState::new();
    let mut decryptor = WillowV1Decryptor { common, prng };

    // Create server.
    let common = WillowCommon {
        kahe: ShellKahe::new(kahe_config.clone(), &public_kahe_seed).unwrap(),
        vahe: ShellVahe::new(ahe_config.clone(), &public_ahe_seed).unwrap(),
    };
    let server = WillowV1Server { common };
    let mut server_state = ServerState::new();

    // Create verifier.
    let common = WillowCommon {
        kahe: ShellKahe::new(kahe_config.clone(), &public_kahe_seed).unwrap(),
        vahe: ShellVahe::new(ahe_config.clone(), &public_ahe_seed).unwrap(),
    };
    let verifier = WillowV1Verifier { common };
    let verifier_state = VerifierState::new();

    // Decryptor generates public key share.
    let public_key_share = decryptor.create_public_key_share(&mut decryptor_state).unwrap();

    // Server handles the public key share.
    server.handle_decryptor_public_key_share(public_key_share, &mut server_state).unwrap();

    // Server creates the public key.
    let public_key = server.create_decryptor_public_key(&server_state).unwrap();

    BaseInputs {
        client,
        decryptor,
        decryptor_state,
        server,
        server_state,
        verifier,
        verifier_state,
        public_key,
    }
}

// Client benchmarks.

struct ClientInputs {
    client: WillowV1Client<ShellKahe, ShellVahe>,
    public_key: DecryptorPublicKey<ShellVahe>,
    plaintext: <ShellKahe as KaheBase>::Plaintext,
}

fn setup_client(args: &Args) -> ClientInputs {
    let inputs = setup_base(args);
    let plaintext = generate_random_unsigned_vector(args.input_length, args.input_domain);
    ClientInputs { client: inputs.client, public_key: inputs.public_key, plaintext }
}

fn run_client(inputs: &mut ClientInputs) {
    let res = inputs
        .client
        .create_client_message(black_box(&inputs.plaintext), black_box(&inputs.public_key));
    let _ = black_box(res); // Prevent optimization.
}

// Server benchmarks.

struct ServerInputs {
    server: WillowV1Server<ShellKahe, ShellVahe>,
    server_state: ServerState<ShellKahe, ShellVahe>,
    ciphertext_contributions: Vec<CiphertextContribution<ShellKahe, ShellVahe>>,
}

struct VerifierInputs {
    verifier: WillowV1Verifier<ShellKahe, ShellVahe>,
    verifier_state: VerifierState<ShellVahe>,
    decryption_request_contributions: Vec<DecryptionRequestContribution<ShellVahe>>,
}

fn setup_verifier_verify_client_message(args: &Args) -> VerifierInputs {
    let mut inputs = setup_base(args);
    let mut decryption_request_contributions = vec![];
    for _ in 0..args.n_iterations {
        // Generates a plaintext and encrypts.
        let client_plaintext =
            generate_random_unsigned_vector(args.input_length, args.input_domain);
        let client_message =
            inputs.client.create_client_message(&client_plaintext, &inputs.public_key).unwrap();
        let (_, decryption_request_contribution) =
            inputs.server.split_client_message(client_message).unwrap();
        decryption_request_contributions.push(decryption_request_contribution);
    }
    VerifierInputs {
        verifier: inputs.verifier,
        verifier_state: inputs.verifier_state,
        decryption_request_contributions,
    }
}

fn run_verifier_verify_client_message(inputs: &mut VerifierInputs) {
    inputs
        .verifier
        .verify_and_include(
            black_box(inputs.decryption_request_contributions.pop().unwrap()),
            black_box(&mut inputs.verifier_state),
        )
        .unwrap();

    // Prevent optimization (verifier state is updated in place)
    let _ = black_box(&mut inputs.verifier_state);
}

fn setup_server_handle_client_message(args: &Args) -> ServerInputs {
    let mut inputs = setup_base(args);
    let mut ciphertext_contributions = vec![];
    for _ in 0..args.n_iterations {
        // Generates a plaintext and encrypts.
        let client_plaintext =
            generate_random_unsigned_vector(args.input_length, args.input_domain);
        let client_message =
            inputs.client.create_client_message(&client_plaintext, &inputs.public_key).unwrap();
        let (ciphertext_contribution, _) =
            inputs.server.split_client_message(client_message).unwrap();
        ciphertext_contributions.push(ciphertext_contribution);
    }
    ServerInputs {
        server: inputs.server,
        server_state: inputs.server_state,
        ciphertext_contributions,
    }
}

fn run_server_handle_client_message(inputs: &mut ServerInputs) {
    inputs
        .server
        .handle_ciphertext_contribution(
            black_box(inputs.ciphertext_contributions.pop().unwrap()),
            black_box(&mut inputs.server_state),
        )
        .unwrap(); // unwrap to check that we are not measuring the time to produce an error.

    // Prevent optimization (server state is updated in place)
    let _ = black_box(&mut inputs.server_state);
}

struct ServerRecoverInputs {
    server: WillowV1Server<ShellKahe, ShellVahe>,
    server_state: ServerState<ShellKahe, ShellVahe>,
}

fn setup_server_recover_aggregation_result(args: &Args) -> ServerRecoverInputs {
    let mut inputs = setup_base(args);

    // Client generates a plaintext and encrypts.
    let client_plaintext = generate_random_unsigned_vector(args.input_length, args.input_domain);
    let client_message =
        inputs.client.create_client_message(&client_plaintext, &inputs.public_key).unwrap();

    // Server splits the client message.
    let (ciphertext_contribution, decryption_request_contribution) =
        inputs.server.split_client_message(client_message).unwrap();

    // Verifier handles its part.
    inputs
        .verifier
        .verify_and_include(decryption_request_contribution, &mut inputs.verifier_state)
        .unwrap();

    // Server handles its part.
    inputs
        .server
        .handle_ciphertext_contribution(ciphertext_contribution, &mut inputs.server_state)
        .unwrap();

    // Verifier creates the partial decryption request.
    let pd_ct = inputs.verifier.create_partial_decryption_request(inputs.verifier_state).unwrap();

    // Decryptor creates partial decryption.
    let pd =
        inputs.decryptor.handle_partial_decryption_request(pd_ct, &inputs.decryptor_state).unwrap();

    // Server handles the partial decryption.
    inputs.server.handle_partial_decryption(pd, &mut inputs.server_state).unwrap();

    ServerRecoverInputs { server: inputs.server, server_state: inputs.server_state }
}

fn run_server_recover_aggregation_result(inputs: &mut ServerRecoverInputs) {
    let res = inputs.server.recover_aggregation_result(black_box(&inputs.server_state)).unwrap();
    let _ = black_box(res); // Prevent optimization.
}

// Decryptor benchmarks.

struct DecryptorInputs {
    decryptor: WillowV1Decryptor<ShellKahe, ShellVahe>,
    decryptor_state: DecryptorState<ShellVahe>,
    partial_decryption_request: PartialDecryptionRequest<ShellVahe>,
}

fn setup_decryptor_partial_decryption(args: &Args) -> DecryptorInputs {
    let mut inputs = setup_base(args);
    for _ in 0..args.max_num_clients {
        // Generates a plaintext and encrypts.
        let client_plaintext =
            generate_random_unsigned_vector(args.input_length, args.input_domain);
        let client_message =
            inputs.client.create_client_message(&client_plaintext, &inputs.public_key).unwrap();

        // Server splits the client message.
        let (ciphertext_contribution, decryption_request_contribution) =
            inputs.server.split_client_message(client_message).unwrap();

        // The server and verifier each handle their part of the client message.
        inputs
            .server
            .handle_ciphertext_contribution(ciphertext_contribution, &mut inputs.server_state)
            .unwrap();
        inputs
            .verifier
            .verify_and_include(decryption_request_contribution, &mut inputs.verifier_state)
            .unwrap();
    }

    // Verifier creates the partial decryption request.
    let pd_ct = inputs.verifier.create_partial_decryption_request(inputs.verifier_state).unwrap();
    DecryptorInputs {
        decryptor: inputs.decryptor,
        decryptor_state: inputs.decryptor_state,
        partial_decryption_request: pd_ct,
    }
}

fn run_decryptor_partial_decryption(inputs: &mut DecryptorInputs) {
    let res = inputs
        .decryptor
        .handle_partial_decryption_request(
            black_box(inputs.partial_decryption_request.clone()),
            black_box(&inputs.decryptor_state),
        )
        .unwrap();
    let _ = black_box(res); // Prevent optimization.
}
