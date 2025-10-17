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

#include "shell_wrapper/kahe.h"

#include <sys/types.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "include/cxx.h"
#include "shell_encryption/rns/coefficient_encoder.h"
#include "shell_encryption/rns/crt_interpolation.h"
#include "shell_encryption/rns/error_distribution.h"
#include "shell_encryption/rns/message_packing.h"
#include "shell_encryption/rns/rns_modulus.h"
#include "shell_encryption/sampler/discrete_gaussian.h"
#include "shell_wrapper/kahe.rs.h"
#include "shell_wrapper/shell_aliases.h"
#include "shell_wrapper/shell_types.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/single_thread_hkdf.rs.h"
#include "shell_wrapper/status.h"
#include "shell_wrapper/status.rs.h"
#include "shell_wrapper/status_macros.h"

using secure_aggregation::MakeFfiStatus;

namespace secure_aggregation {

absl::StatusOr<KahePublicParameters> CreateKahePublicParameters(
    const RnsContextConfig& rns_context_config, int log_kahe_plaintext_modulus,
    int num_public_polynomials, absl::string_view public_seed) {
  // Create RNS context (instantiated with BGV)
  SECAGG_ASSIGN_OR_RETURN(
      auto rns_context,
      RnsContext::Create(rns_context_config.log_n, rns_context_config.qs,
                         /*ps=*/{}, rns_context_config.t));
  auto rns_context_ptr =
      std::make_unique<const RnsContext>(std::move(rns_context));
  std::vector<const rlwe::PrimeModulus<ModularInt>*> moduli =
      rns_context_ptr->MainPrimeModuli();

  // Create RNS representation for plaintext modulus
  BigInteger kahe_plaintext_modulus = static_cast<BigInteger>(1)
                                      << log_kahe_plaintext_modulus;
  std::vector<ModularInt> zs;
  for (int i = 0; i < moduli.size(); ++i) {
    const auto mod_params_qi = moduli[i]->ModParams();
    Integer qi = mod_params_qi->modulus;
    BigInteger qi_big = static_cast<BigInteger>(qi);
    BigInteger plaintext_modulus_mod_qi = kahe_plaintext_modulus % qi_big;
    SECAGG_ASSIGN_OR_RETURN(
        ModularInt z,
        ModularInt::ImportInt(static_cast<Integer>(plaintext_modulus_mod_qi),
                              mod_params_qi));
    zs.push_back(std::move(z));
  }
  auto plaintext_modulus_rns = RnsInt{zs};

  // Generate public parameters ("a").
  auto prg_public_prng = Prng::Create(public_seed).value();
  std::vector<RnsPolynomial> public_polynomials;
  public_polynomials.reserve(num_public_polynomials);
  for (int i = 0; i < num_public_polynomials; ++i) {
    auto a = RnsPolynomial::SampleUniform(rns_context_config.log_n,
                                          prg_public_prng.get(), moduli)
                 .value();
    public_polynomials.push_back(std::move(a));
  }

  // Create an encoder and an error sampler that will be used in each call to
  // encrypt/decrypt.
  SECAGG_ASSIGN_OR_RETURN(
      auto prg_encoder,
      rlwe::CoefficientEncoder<ModularInt>::Create(rns_context_ptr.get()));
  SECAGG_ASSIGN_OR_RETURN(
      auto error_dg_sampler,
      rlwe::DiscreteGaussianSampler<Integer>::Create(kPrgErrorS));

  std::vector<BigInteger> modulus_hats =
      rlwe::RnsModulusComplements<ModularInt, BigInteger>(moduli);

  auto level = moduli.size() - 1;
  SECAGG_ASSIGN_OR_RETURN(std::vector<ModularInt> modulus_hats_invs,
                          rns_context_ptr->MainPrimeModulusCrtFactors(level));

  return KahePublicParameters{
      .context = std::move(rns_context_ptr),
      .plaintext_modulus = kahe_plaintext_modulus,
      .plaintext_modulus_rns = plaintext_modulus_rns,
      .moduli = std::move(moduli),
      .modulus_hats = std::move(modulus_hats),
      .modulus_hats_invs = std::move(modulus_hats_invs),
      .encoder = std::move(prg_encoder),
      .public_polynomials = std::move(public_polynomials),
      .error_dg_sampler = std::move(error_dg_sampler),
  };
}

absl::StatusOr<RnsPolynomial> GenerateSecretKey(
    const KahePublicParameters& params, Prng* prng) {
  // Create discrete Gaussian sampler.
  SECAGG_ASSIGN_OR_RETURN(
      auto secret_sampler,
      rlwe::DiscreteGaussianSampler<Integer>::Create(kPrgSecretS));

  // Sample secret coefficients, and encode as RNS polynomial.
  int num_prg_coeffs = 1 << params.context->LogN();
  std::vector<std::vector<ModularInt>> prg_secret_rns_coeffs(
      params.moduli.size());
  for (int j = 0; j < num_prg_coeffs; ++j) {
    SECAGG_ASSIGN_OR_RETURN(Integer value, secret_sampler->Sample(*prng));
    // Convert `value` to balanced representation mod q_i for each q_i.
    for (int i = 0; i < params.moduli.size(); ++i) {
      Integer value_balanced_qi = value;
      if (value > rlwe::DiscreteGaussianSampler<Integer>::kNegativeThreshold) {
        // `value` is a negative Gaussian sample, represented as a large
        // unsigned integer.
        value_balanced_qi = params.moduli[i]->Modulus() - (-value);
      }
      SECAGG_ASSIGN_OR_RETURN(
          ModularInt value_mod_qi,
          ModularInt::ImportInt(value_balanced_qi,
                                params.moduli[i]->ModParams()));
      prg_secret_rns_coeffs[i].push_back(value_mod_qi);
    }
  }
  SECAGG_ASSIGN_OR_RETURN(
      auto prg_secret, RnsPolynomial::Create(std::move(prg_secret_rns_coeffs),
                                             /*is_ntt=*/false));

  if (!prg_secret.IsNttForm()) {
    SECAGG_RETURN_IF_ERROR(prg_secret.ConvertToNttForm(params.moduli));
  }

  return prg_secret;
}

namespace internal {
absl::StatusOr<RnsPolynomial> EncryptPolynomial(
    const RnsPolynomial& plaintext, const RnsPolynomial& secret_key,
    RnsInt plaintext_modulus_rns, int log_n, const RnsPolynomial& a,
    absl::Span<const rlwe::PrimeModulus<ModularInt>* const> moduli,
    const rlwe::DiscreteGaussianSampler<Integer>* dg_sampler, Prng* prng) {
  // Sample the error term e (mod Q) from the error distribution.
  SECAGG_ASSIGN_OR_RETURN(RnsPolynomial c,
                          rlwe::SampleDiscreteGaussian<ModularInt>(
                              log_n, moduli, dg_sampler, prng));

  // c = e * t (mod Q).
  SECAGG_RETURN_IF_ERROR(c.MulInPlace(plaintext_modulus_rns, moduli));

  // c = e * t + m (mod Q).
  SECAGG_RETURN_IF_ERROR(c.AddInPlace(plaintext, moduli));
  if (!c.IsNttForm()) {
    SECAGG_RETURN_IF_ERROR(c.ConvertToNttForm(moduli));
  }

  // c = e * t + m + a * key (mod Q).
  SECAGG_RETURN_IF_ERROR(c.FusedMulAddInPlace(a, secret_key, moduli));
  return c;
}

absl::StatusOr<RnsPolynomial> DecryptPolynomial(
    const RnsPolynomial& ciphertext, const RnsPolynomial& secret_key,
    const RnsPolynomial& a,
    absl::Span<const rlwe::PrimeModulus<ModularInt>* const> moduli) {
  // p = a * k (mod Q).
  SECAGG_ASSIGN_OR_RETURN(RnsPolynomial p, secret_key.Mul(a, moduli));

  // p = - a * k (mod Q).
  SECAGG_RETURN_IF_ERROR(p.NegateInPlace(moduli));

  // p = c - a * k (mod Q).
  SECAGG_RETURN_IF_ERROR(p.AddInPlace(ciphertext, moduli));
  return p;
}

std::vector<std::vector<BigInteger>> PackMessagesRaw(const Integer* messages,
                                                     int num_messages,
                                                     Integer packing_base,
                                                     int num_packing,
                                                     int num_coeffs) {
  // NOTE: temporary implementation that copies the input. We can avoid copying
  // by modifying the original PackMessages function to work with pointers
  // directly.
  std::vector<Integer> messages_copy;
  messages_copy.reserve(num_messages);
  for (int i = 0; i < num_messages; ++i) {
    messages_copy.push_back(messages[i]);
  }
  return rlwe::PackMessages<Integer, BigInteger>(messages_copy, packing_base,
                                                 num_packing, num_coeffs);
}

int UnpackMessagesRaw(
    const std::vector<std::vector<BigInteger>>& packed_messages,
    uint64_t packing_base, int num_packing, int output_values_length,
    uint64_t* output_values) {
  std::vector<uint64_t> unpacked_messages =
      rlwe::UnpackMessages(packed_messages, packing_base, num_packing);

  auto count = std::min(static_cast<size_t>(output_values_length),
                        unpacked_messages.size());
  std::copy_n(unpacked_messages.begin(), count, output_values);
  return count;
}

}  // namespace internal

absl::StatusOr<std::vector<RnsPolynomial>> EncodeAndEncryptVector(
    std::vector<std::vector<BigInteger>>& packed_messages,
    const RnsPolynomial& secret_key, const KahePublicParameters& params,
    Prng* prng) {
  std::vector<RnsPolynomial> ciphertexts;

  if (packed_messages.size() > params.public_polynomials.size()) {
    return absl::InvalidArgumentError("Input too long");
  }

  for (int i = 0; i < packed_messages.size(); ++i) {
    const auto& packed_message = packed_messages[i];
    const RnsPolynomial& a = params.public_polynomials[i];
    SECAGG_ASSIGN_OR_RETURN(
        RnsPolynomial plaintext,
        params.encoder.EncodeBgv<BigInteger>(
            packed_message, params.plaintext_modulus, params.moduli));
    SECAGG_ASSIGN_OR_RETURN(
        RnsPolynomial ciphertext,
        internal::EncryptPolynomial(plaintext, secret_key,
                                    params.plaintext_modulus_rns,
                                    params.context->LogN(), a, params.moduli,
                                    params.error_dg_sampler.get(), prng));

    ciphertexts.push_back(std::move(ciphertext));
  }
  return ciphertexts;
}

absl::StatusOr<std::vector<std::vector<BigInteger>>> DecodeAndDecryptVector(
    absl::Span<const RnsPolynomial> ciphertexts,
    const RnsPolynomial& secret_key, const KahePublicParameters& params) {
  std::vector<std::vector<BigInteger>> all_packed_messages;
  for (int i = 0; i < ciphertexts.size(); ++i) {
    const auto& ciphertext = ciphertexts[i];
    const RnsPolynomial& a = params.public_polynomials[i];
    SECAGG_ASSIGN_OR_RETURN(
        RnsPolynomial plaintext,
        internal::DecryptPolynomial(ciphertext, secret_key, a, params.moduli));
    SECAGG_ASSIGN_OR_RETURN(
        std::vector<BigInteger> packed_messages,
        params.encoder.DecodeBgv<BigInteger>(
            std::move(plaintext), params.plaintext_modulus, params.moduli,
            params.modulus_hats, params.modulus_hats_invs));
    all_packed_messages.push_back(std::move(packed_messages));
  }
  return all_packed_messages;
}

}  // namespace secure_aggregation

FfiStatus CreateKahePublicParametersWrapper(uint64_t log_n, uint64_t log_t,
                                            rust::Slice<const uint64_t> qs,
                                            uint64_t num_public_polynomials,
                                            rust::Slice<const uint8_t> seed,
                                            KahePublicParametersWrapper* out) {
  if (out == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  // Parse the RNS config
  constexpr int dummy_rns_plaintext_modulus = 2;  // Unused for KAHE
  secure_aggregation::RnsContextConfig rns_context_config =
      secure_aggregation::ParseRnsContextConfig(
          log_n, dummy_rns_plaintext_modulus, qs.data(), qs.size());

  auto statusor = secure_aggregation::CreateKahePublicParameters(
      rns_context_config, log_t, num_public_polynomials,
      absl::string_view(reinterpret_cast<const char*>(seed.data()),
                        seed.size()));
  if (!statusor.ok()) {
    return MakeFfiStatus(statusor.status());
  }
  out->ptr = std::make_unique<secure_aggregation::KahePublicParameters>(
      std::move(statusor.value()));
  return MakeFfiStatus();
}

FfiStatus GenerateSecretKeyWrapper(const KahePublicParametersWrapper& params,
                                   SingleThreadHkdfWrapper* prng,
                                   RnsPolynomialWrapper* out) {
  if (prng == nullptr || prng->ptr == nullptr || params.ptr == nullptr ||
      out == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  auto statusor =
      secure_aggregation::GenerateSecretKey(*params.ptr, prng->ptr.get());
  if (!statusor.ok()) {
    return MakeFfiStatus(statusor.status());
  }
  out->ptr = std::make_unique<secure_aggregation::RnsPolynomial>(
      std::move(statusor.value()));
  return MakeFfiStatus();
}

FfiStatus Encrypt(rust::Slice<const uint64_t> input_values,
                  uint64_t packing_base, uint64_t num_packing,
                  const RnsPolynomialWrapper& secret_key,
                  const KahePublicParametersWrapper& params,
                  SingleThreadHkdfWrapper* prng, RnsPolynomialVecWrapper* out) {
  // Validate the wrappers.
  if (secret_key.ptr == nullptr || params.ptr == nullptr || prng == nullptr ||
      prng->ptr == nullptr || out == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  // Packing parameters must be valid, e.g. checked on the Rust side.
  int num_coeffs = 1 << params.ptr->context->LogN();
  std::vector<std::vector<secure_aggregation::BigInteger>> packed_messages =
      secure_aggregation::internal::PackMessagesRaw(
          input_values.data(), input_values.size(), packing_base, num_packing,
          num_coeffs);

  auto ciphertext_vec = secure_aggregation::EncodeAndEncryptVector(
      packed_messages, *secret_key.ptr, *params.ptr, prng->ptr.get());

  if (!ciphertext_vec.ok()) {
    return MakeFfiStatus(ciphertext_vec.status());
  }
  out->len = ciphertext_vec.value().size();
  out->ptr = std::make_unique<std::vector<secure_aggregation::RnsPolynomial>>(
      std::move(ciphertext_vec.value()));
  return MakeFfiStatus();
}

FfiStatus Decrypt(uint64_t packing_base, uint64_t num_packing,
                  const RnsPolynomialVecWrapper& ciphertexts,
                  const RnsPolynomialWrapper& secret_key,
                  const KahePublicParametersWrapper& params,
                  rust::Slice<uint64_t> output_values, uint64_t* n_written) {
  // Validate the wrappers.
  if (secret_key.ptr == nullptr || params.ptr == nullptr ||
      ciphertexts.ptr == nullptr || n_written == nullptr) {
    return MakeFfiStatus(absl::InvalidArgumentError(
        secure_aggregation::kNullPointerErrorMessage));
  }

  // Secret key may be in coeff form after deserialization from an AHE
  // plaintext, so convert to NTT form if needed.
  if (!secret_key.ptr->IsNttForm()) {
    auto status = secret_key.ptr->ConvertToNttForm(params.ptr->moduli);
    if (!status.ok()) {
      return MakeFfiStatus(status);
    }
  }

  auto messages = secure_aggregation::DecodeAndDecryptVector(
      *ciphertexts.ptr, *secret_key.ptr, *params.ptr);
  if (!messages.ok()) {
    return MakeFfiStatus(messages.status());
  }

  *n_written = secure_aggregation::internal::UnpackMessagesRaw(
      messages.value(), packing_base, num_packing, output_values.size(),
      output_values.data());

  return MakeFfiStatus();
}
