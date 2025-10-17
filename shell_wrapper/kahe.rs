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

//! Rust wrapper around the simplified C++ API for Key Additive Homomorphic
//! Encryption.

use shell_types::{Moduli, RnsContextRef, RnsPolynomial, RnsPolynomialVec};
use single_thread_hkdf::{SeedWrapper, SingleThreadHkdfWrapper};
use status::rust_status_from_cpp;
use std::marker::PhantomData;
use std::mem::MaybeUninit;

#[cxx::bridge]
mod ffi {
    /// Owned KahePublicParameters behind a unique_ptr.
    pub struct KahePublicParametersWrapper {
        pub ptr: UniquePtr<KahePublicParameters>,
    }

    unsafe extern "C++" {
        include!("shell_wrapper/kahe.h");
        include!("shell_wrapper/shell_types.h");

        #[namespace = "secure_aggregation"]
        type KahePublicParameters;

        type FfiStatus = shell_types::ffi::FfiStatus;
        type ModuliWrapper = shell_types::ffi::ModuliWrapper;
        #[namespace = "secure_aggregation"]
        type RnsContext = shell_types::ffi::RnsContext;
        type RnsPolynomialWrapper = shell_types::ffi::RnsPolynomialWrapper;
        type RnsPolynomialVecWrapper = shell_types::ffi::RnsPolynomialVecWrapper;
        type SingleThreadHkdfWrapper = single_thread_hkdf::SingleThreadHkdfWrapper;

        pub unsafe fn CreateKahePublicParametersWrapper(
            log_n: u64,
            log_t: u64,
            qs: &[u64],
            num_public_polynomials: u64,
            seed: &[u8],
            out: *mut KahePublicParametersWrapper,
        ) -> FfiStatus;

        pub unsafe fn CreateModuliWrapperFromKaheParams(
            params: &KahePublicParametersWrapper,
        ) -> ModuliWrapper;

        pub unsafe fn GetRnsContextFromKaheParams(
            params: &KahePublicParametersWrapper,
        ) -> *const RnsContext;

        pub unsafe fn GenerateSecretKeyWrapper(
            params: &KahePublicParametersWrapper,
            prng: *mut SingleThreadHkdfWrapper,
            out: *mut RnsPolynomialWrapper,
        ) -> FfiStatus;

        pub unsafe fn Encrypt(
            input_values: &[u64],
            packing_base: u64,
            num_packing: u64,
            secret_key: &RnsPolynomialWrapper,
            params: &KahePublicParametersWrapper,
            prng: *mut SingleThreadHkdfWrapper,
            out: *mut RnsPolynomialVecWrapper,
        ) -> FfiStatus;

        pub unsafe fn Decrypt(
            packing_base: u64,
            num_packing: u64,
            ciphertexts: &RnsPolynomialVecWrapper,
            secret_key: &RnsPolynomialWrapper,
            params: &KahePublicParametersWrapper,
            output_values: &mut [u64],
            n_written: *mut u64,
        ) -> FfiStatus;
    }
}
pub use ffi::KahePublicParametersWrapper;

/// Creates new public parameters for KAHE. `num_public_polynomials` is the
/// number of public "a" polynomials to generate from the public `seed`. Each
/// call to `encrypt` using the same secret key must use a different public
/// polynomial. `log_t` is the number of bits of the KAHE plaintext modulus (q1
/// from [Willow](https://eprint.iacr.org/2024/936.pdf)).
pub fn create_public_parameters(
    log_n: u64,
    log_t: u64,
    qs: &[u64],
    num_public_polynomials: usize,
    seed: &SeedWrapper,
) -> Result<KahePublicParametersWrapper, status::StatusError> {
    let mut out = MaybeUninit::<KahePublicParametersWrapper>::zeroed();
    // SAFETY: No lifetime constraints (the new `PublicParametersWrapper` does not
    // keep any reference to the seed). Only reads the `qs` buffer within a valid
    // range.
    rust_status_from_cpp(unsafe {
        ffi::CreateKahePublicParametersWrapper(
            log_n,
            log_t,
            qs,
            num_public_polynomials as u64,
            seed.as_bytes(),
            out.as_mut_ptr(),
        )
    })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

/// Returns RNS moduli, containing pointers to the moduli in the public
/// parameters.
pub fn get_moduli<'a>(params: &'a KahePublicParametersWrapper) -> Moduli<'a> {
    // SAFETY: `moduli` contains raw pointers to the moduli in `params`, but the bindings
    // don't know that, so we add a lifetime annotation with PhantomData. After
    // that, both `params` and `moduli` live for at least `'a`.
    let moduli = unsafe { ffi::CreateModuliWrapperFromKaheParams(params) };
    Moduli { moduli, phantom: PhantomData }
}

/// Returns an RnsContextRef, containing a pointer to the RNS context in the
/// public parameters.
pub fn get_rns_context_ref<'a>(params: &'a KahePublicParametersWrapper) -> RnsContextRef<'a> {
    // SAFETY: `rns_context` contains a raw pointer to the RNS context in
    // `params`, but the bindings don't know that, so we add a lifetime annotation
    // with PhantomData. After that, both `params` and `rns_context` live for at
    // least `
    let rns_context = unsafe { ffi::GetRnsContextFromKaheParams(params) };
    RnsContextRef { rns_context, phantom: PhantomData }
}

/// Generates a BGV secret key.
pub fn generate_secret_key(
    params: &KahePublicParametersWrapper,
    prng: &mut SingleThreadHkdfWrapper,
) -> Result<RnsPolynomial, status::StatusError> {
    let mut out = MaybeUninit::<RnsPolynomial>::zeroed();
    // SAFETY: `out` pointer is valid, no references to `params` or `prng` are kept.
    rust_status_from_cpp(unsafe { ffi::GenerateSecretKeyWrapper(params, prng, out.as_mut_ptr()) })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

/// Encrypts a vector of values.
///
/// The values are encoded as a polynomial, then encrypted with the secret key
/// and the public polynomial at `public_polynomial_index` in `params`.
pub fn encrypt(
    input_values: &[u64],
    secret_key: &RnsPolynomial,
    params: &KahePublicParametersWrapper,
    packing_base: u64,
    num_packing: usize,
    prng: &mut SingleThreadHkdfWrapper,
) -> Result<RnsPolynomialVec, status::StatusError> {
    let mut out = MaybeUninit::<RnsPolynomialVec>::zeroed();
    // SAFETY: No lifetime constraints (`Encrypt` creates a new polynomial which
    // does not keep any reference to the inputs). `Encrypt` reads the
    // `input_values` buffer within a valid range.
    rust_status_from_cpp(unsafe {
        ffi::Encrypt(
            input_values,
            packing_base,
            num_packing as u64,
            secret_key,
            params,
            prng,
            out.as_mut_ptr(),
        )
    })?;
    // SAFETY: `out` is safely initialized if we get to this point.
    Ok(unsafe { out.assume_init() })
}

/// Decrypts a ciphertext that was encrypted with `secret_key` and the public
/// polynomial a stored at `public_polynomial_index` in `params`. Writes the
/// decrypted values into `output_values`. Returns the number of values written.
///
/// This low-level API works with slices. The caller can allocate vectors if
/// they want. Using an uninitialized Vec::with_capacity works too, but then we
/// need to manually update the length with `unsafe {
/// output_values.set_len(n_messages_written) }` because Rust doesn't know that
/// C has written into the vector.
pub fn decrypt(
    ciphertext: &RnsPolynomialVec,
    secret_key: &RnsPolynomial,
    params: &KahePublicParametersWrapper,
    packing_base: u64,
    num_packing: usize,
    output_values: &mut [u64],
) -> Result<usize, status::StatusError> {
    // SAFETY:  No lifetime constraints (`DecryptionResult` just holds two ints and
    // does not keep any reference to the inputs). `Decrypt` only modifies the
    // `output_values` buffer within a valid range.
    let mut n_written = 0u64;
    rust_status_from_cpp(unsafe {
        ffi::Decrypt(
            packing_base,
            num_packing as u64,
            ciphertext,
            secret_key,
            params,
            output_values,
            &mut n_written,
        )
    })?;
    Ok(n_written as usize)
}
