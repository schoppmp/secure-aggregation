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

#include <sys/stat.h>
#include <sys/types.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/types/span.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "include/cxx.h"
#include "shell_encryption/rns/error_distribution.h"
#include "shell_encryption/rns/message_packing.h"
#include "shell_encryption/rns/testing/testing_utils.h"
#include "shell_encryption/sampler/discrete_gaussian.h"
#include "shell_wrapper/kahe.rs.h"
#include "shell_wrapper/shell_aliases.h"
#include "shell_wrapper/shell_types.h"
#include "shell_wrapper/shell_types.rs.h"
#include "shell_wrapper/single_thread_hkdf.h"
#include "shell_wrapper/single_thread_hkdf.rs.h"
#include "shell_wrapper/status.h"
#include "shell_wrapper/status.rs.h"
#include "shell_wrapper/status_matchers.h"
#include "shell_wrapper/testing_utils.h"

namespace secure_aggregation {
namespace {

using secure_aggregation::secagg_internal::StatusIs;
using ::testing::IsNull;

constexpr int kLogN = 12;
constexpr int kNumCoeffs = 1 << kLogN;
const std::vector<uint64_t> kQs = {1125899906826241ULL,
                                   1125899906629633ULL};  // q ~ 2^100

// We need  t * e in [-q/2, q/2).
// We take kLogT < 100 - 1 - log2(kTailBoundMultiplier) - log2(kPrgErrorS)
constexpr int kLogT = 93;
const BigInteger kT = BigInteger(1) << kLogT;

const RnsContextConfig kRnsContextConfig = {
    .log_n = kLogN,
    .qs = kQs,
    .t = 2,  // Dummy RNS plaintext modulus here
};

rust::Slice<const uint64_t> ToRustSlice(absl::Span<const uint64_t> s) {
  return rust::Slice<const uint64_t>(s.data(), s.size());
}

using ::ToRustSlice;  // Import into namespace for correct resolution.

TEST(KaheTest, SamplingSmokeTest) {
  constexpr int num_public_polynomials = 1;
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string public_seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto const params,
      CreateKahePublicParameters(kRnsContextConfig, kLogT,
                                 num_public_polynomials, public_seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto error_dg_sampler,
      rlwe::DiscreteGaussianSampler<Integer>::Create(kPrgErrorS));

  // Error should not be zero w.h.p.
  SECAGG_ASSERT_OK_AND_ASSIGN(RnsPolynomial c1,
                              rlwe::SampleDiscreteGaussian<ModularInt>(
                                  params.context->LogN(), params.moduli,
                                  error_dg_sampler.get(), prng.get()));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto c2,
      RnsPolynomial::CreateZero(params.context->LogN(), params.moduli));
  EXPECT_NE(c1, c2);

  // Error should be small w.h.p.
  for (int i = 0; i < params.moduli.size(); ++i) {
    // For a small integer c, |c| mod q = |c|, so we check that the RNS
    // representation of |c| is small for each modulus.
    Integer q = params.moduli[i]->Modulus();
    Integer q_half = q >> 1;
    for (auto& coeff : c1.Coeffs()[i]) {
      // Get |c| from the Montgomery representation.
      Integer c = coeff.ExportInt(params.moduli[i]->ModParams());
      Integer abs;
      if (c > q_half) {
        ASSERT_LT(c, q);
        abs = q - c;
      } else {
        abs = c;
      }
      EXPECT_LT(abs,
                rlwe::DiscreteGaussianSampler<Integer>::kTailBoundMultiplier *
                    kPrgErrorS);
    }
  }
}

TEST(KaheTest, KeyGeneration) {
  constexpr int num_public_polynomials = 4;
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string public_seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto const params,
      CreateKahePublicParameters(kRnsContextConfig, kLogT,
                                 num_public_polynomials, public_seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));

  // Generate two keys and check that they are different.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto key1, GenerateSecretKey(params, prng.get()));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto key2, GenerateSecretKey(params, prng.get()));
  EXPECT_NE(key1, key2);
}

TEST(KaheTest, EncryptDecrypt) {
  constexpr int num_public_polynomials = 2;
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string public_seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto const params,
      CreateKahePublicParameters(kRnsContextConfig, kLogT,
                                 num_public_polynomials, public_seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto error_dg_sampler,
      rlwe::DiscreteGaussianSampler<Integer>::Create(kPrgErrorS));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto key, GenerateSecretKey(params, prng.get()));

  // Encrypt a random input.
  int num_messages = 10;
  std::vector<BigInteger> messages =
      testing::SampleUint256Messages(num_messages, kT);
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto input0, params.encoder.EncodeBgv<BigInteger>(
                       messages, params.plaintext_modulus, params.moduli));
  auto a0 = params.public_polynomials[0];
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto ciphertext0,
      internal::EncryptPolynomial(input0, key, params.plaintext_modulus_rns,
                                  params.context->LogN(), a0, params.moduli,
                                  error_dg_sampler.get(), prng.get()));

  // Check that decryption works. Decoded input is padded with 0s, so we don't
  // compare with the messages directly.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto decrypted0,
      internal::DecryptPolynomial(ciphertext0, key, a0, params.moduli));
  EXPECT_EQ(params.encoder
                .DecodeBgv<BigInteger>(input0, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value(),
            params.encoder
                .DecodeBgv<BigInteger>(decrypted0, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value());

  // Encrypt another input with a different public polynomial.
  num_messages = 100;
  messages = testing::SampleUint256Messages(num_messages, kT);

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto input1, params.encoder.EncodeBgv<BigInteger>(
                       messages, params.plaintext_modulus, params.moduli));
  EXPECT_NE(params.encoder
                .DecodeBgv<BigInteger>(input1, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value(),
            params.encoder
                .DecodeBgv<BigInteger>(input0, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value());

  auto a1 = params.public_polynomials[0];
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto ciphertext1,
      internal::EncryptPolynomial(input1, key, params.plaintext_modulus_rns,
                                  params.context->LogN(), a1, params.moduli,
                                  error_dg_sampler.get(), prng.get()));
  EXPECT_NE(ciphertext0, ciphertext1);

  // Check that decryption still works.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto decrypted1,
      internal::DecryptPolynomial(ciphertext1, key, a1, params.moduli));
  EXPECT_EQ(params.encoder
                .DecodeBgv<BigInteger>(input1, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value(),
            params.encoder
                .DecodeBgv<BigInteger>(decrypted1, params.plaintext_modulus,
                                       params.moduli, params.modulus_hats,
                                       params.modulus_hats_invs)
                .value());
}

TEST(KaheTest, VectorEncryptDecrypt) {
  constexpr int num_public_polynomials = 10;
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string public_seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto const params,
      CreateKahePublicParameters(kRnsContextConfig, kLogT,
                                 num_public_polynomials, public_seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto key, GenerateSecretKey(params, prng.get()));

  // Encrypt random input vector that uses all the polynomial coefficients.
  constexpr int num_polynomials = 10;
  std::vector<std::vector<BigInteger>> all_packed_messages;
  std::vector<BigInteger> packed_messages;
  packed_messages.reserve(kNumCoeffs);
  for (int i = 0; i < num_polynomials; ++i) {
    auto packed_messages = testing::SampleUint256Messages(kNumCoeffs, kT);
    all_packed_messages.push_back(std::move(packed_messages));
  }

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto ciphertexts,
      EncodeAndEncryptVector(all_packed_messages, key, params, prng.get()));

  SECAGG_ASSERT_OK_AND_ASSIGN(auto decrypted,
                              DecodeAndDecryptVector(ciphertexts, key, params));

  EXPECT_EQ(all_packed_messages, decrypted);
}

TEST(KaheTest, PackAndEncrypt) {
  constexpr int num_packing = 8;
  constexpr int num_public_polynomials = 2;
  constexpr int num_messages = 30;
  constexpr uint64_t packing_base = 2;

  SECAGG_ASSERT_OK_AND_ASSIGN(std::string public_seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto const params,
      CreateKahePublicParameters(kRnsContextConfig, kLogT,
                                 num_public_polynomials, public_seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(std::string seed, Prng::GenerateSeed());
  SECAGG_ASSERT_OK_AND_ASSIGN(auto prng, Prng::Create(seed));
  SECAGG_ASSERT_OK_AND_ASSIGN(auto key, GenerateSecretKey(params, prng.get()));

  std::vector<Integer> input_vec =
      rlwe::testing::SampleMessages(num_messages, packing_base);

  std::vector<std::vector<secure_aggregation::BigInteger>> packed_messages =
      rlwe::PackMessages<Integer, BigInteger>(input_vec, packing_base,
                                              num_packing, kNumCoeffs);
  EXPECT_EQ(packed_messages.size(),
            1);  // Only one polynomial needed.

  // Check that RawPack works as expected.
  int num_coeffs = 1 << params.context->LogN();
  EXPECT_EQ(num_coeffs, kNumCoeffs);

  std::vector<std::vector<secure_aggregation::BigInteger>> raw_packed_messages =
      secure_aggregation::internal::PackMessagesRaw(
          input_vec.data(), input_vec.size(), packing_base, num_packing,
          num_coeffs);
  EXPECT_EQ(raw_packed_messages, packed_messages);

  SECAGG_ASSERT_OK_AND_ASSIGN(auto ciphertexts,
                              secure_aggregation::EncodeAndEncryptVector(
                                  packed_messages, key, params, prng.get()));

  SECAGG_ASSERT_OK_AND_ASSIGN(
      auto decrypted,
      secure_aggregation::DecodeAndDecryptVector(ciphertexts, key, params));
  EXPECT_EQ(decrypted.size(), 1);  // Only one ciphertext polynomial needed.

  std::vector<Integer> unpacked_messages =
      rlwe::UnpackMessages(decrypted, packing_base, num_packing);

  // Check that UnpackRaw works as expected.
  uint64_t decrypted_buffer[2 * num_messages];
  auto n_messages_written = secure_aggregation::internal::UnpackMessagesRaw(
      decrypted, packing_base, num_packing, 2 * num_messages, decrypted_buffer);
  EXPECT_EQ(n_messages_written, 2 * num_messages);
  EXPECT_EQ(absl::MakeSpan(decrypted_buffer, num_messages),
            absl::MakeSpan(unpacked_messages).subspan(0, num_messages));

  // Check decrypted messages and padding.
  EXPECT_EQ(absl::MakeSpan(unpacked_messages).subspan(0, num_messages),
            absl::MakeSpan(input_vec).subspan(0, num_messages));
  EXPECT_THAT(
      absl::MakeSpan(unpacked_messages)
          .subspan(num_messages, unpacked_messages.size() - num_messages),
      ::testing::Each(::testing::Eq(0)));
}

TEST(KaheTest, RawVectorEncryptOnePolynomial) {
  constexpr int num_packing = 2;
  constexpr uint64_t num_public_polynomials = 2;
  FfiStatus status;
  std::unique_ptr<std::string> public_seed;
  status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  KahePublicParametersWrapper params;
  status = CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  std::unique_ptr<std::string> private_seed;
  status = GenerateSingleThreadHkdfSeed(private_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  SingleThreadHkdfWrapper prng;
  status = CreateSingleThreadHkdf(ToRustSlice(*private_seed), prng);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  RnsPolynomialWrapper key;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(params, &prng, &key)));

  // Generate random messages that fit on one polynomial.
  constexpr int num_messages = 10;
  constexpr uint64_t packing_base = 10;
  std::vector<Integer> input_values =
      rlwe::testing::SampleMessages(num_messages, packing_base);

  RnsPolynomialVecWrapper ciphertexts;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(Encrypt(ToRustSlice(input_values), packing_base,
                              num_packing, key, params, &prng, &ciphertexts)));

  // Check that decryption works when we decrypt only what we need.
  uint64_t decrypted[num_messages];
  uint64_t n_written;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      Decrypt(packing_base, num_packing, ciphertexts, key, params,
              rust::Slice(decrypted, num_messages), &n_written)));

  // Filled the whole buffer with right messages.
  EXPECT_EQ(num_messages, n_written);
  EXPECT_EQ(absl::MakeSpan(decrypted), absl::MakeSpan(input_values));

  // Check that decryption still work when we receive some padding.
  constexpr uint64_t buffer_length =
      2 * kNumCoeffs * num_packing;  // Room for 2 plaintext polynomials.
  constexpr uint64_t padded_length =
      kNumCoeffs * num_packing;  // What the padded input really needs.
  uint64_t decrypted_long[buffer_length] = {};
  decrypted_long[padded_length - 1] = 42;  // Check that we overwrite this.
  decrypted_long[padded_length] = 42;  // Check that we don't overwrite this.
  n_written = 0;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      Decrypt(packing_base, num_packing, ciphertexts, key, params,
              rust::Slice(decrypted_long, buffer_length), &n_written)));

  // Decrypt doesn't fill the whole buffer.
  EXPECT_EQ(n_written, padded_length);

  // The non-zero messages are identical.
  EXPECT_EQ(absl::MakeSpan(decrypted_long).subspan(0, num_messages),
            absl::MakeSpan(input_values));

  // Decrypted messages are padded to zero up to the end of the polynomial.
  EXPECT_THAT(absl::MakeSpan(decrypted_long)
                  .subspan(num_messages, padded_length - num_messages),
              ::testing::Each(::testing::Eq(0)));

  // The canary is unchanged.
  EXPECT_EQ(decrypted_long[padded_length], 42);
}

TEST(KaheTest, RawVectorEncryptTwoPolynomials) {
  constexpr int num_packing = 8;
  constexpr uint64_t num_public_polynomials = 2;
  FfiStatus status;
  std::unique_ptr<std::string> public_seed;
  status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  KahePublicParametersWrapper params;
  status = CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  std::unique_ptr<std::string> private_seed;
  status = GenerateSingleThreadHkdfSeed(private_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  SingleThreadHkdfWrapper prng;
  status = CreateSingleThreadHkdf(ToRustSlice(*private_seed), prng);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  RnsPolynomialWrapper key;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(params, &prng, &key)));

  // Generate random messages that need two polynomials.
  constexpr int num_messages = kNumCoeffs * num_packing + 10;
  constexpr uint64_t packing_base = 2;
  std::vector<Integer> input_vec =
      rlwe::testing::SampleMessages(num_messages, packing_base);
  uint64_t input_values[num_messages];
  for (int i = 0; i < num_messages; ++i) {
    input_values[i] = input_vec[i];
  }

  RnsPolynomialVecWrapper ciphertexts;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(Encrypt(ToRustSlice(input_values), packing_base,
                              num_packing, key, params, &prng, &ciphertexts)));

  // Check that decryption works when we decrypt only what we need.
  uint64_t decrypted[num_messages];
  uint64_t n_written;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      Decrypt(packing_base, num_packing, ciphertexts, key, params,
              rust::Slice(decrypted, num_messages), &n_written)));

  EXPECT_EQ(n_written, num_messages);

  for (int i = 0; i < num_messages; ++i) {
    EXPECT_EQ(input_values[i], decrypted[i]);
  }

  // Check that decryption is padded properly.
  constexpr int num_ciphertext_polynomials =
      2;  // Input fits on two polynomials.
  constexpr int padded_length =
      kNumCoeffs * num_packing * num_ciphertext_polynomials;
  constexpr int buffer_length = padded_length * 2;
  uint64_t decrypted_padded[buffer_length];
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      Decrypt(packing_base, num_packing, ciphertexts, key, params,
              rust::Slice(decrypted_padded, buffer_length), &n_written)));

  EXPECT_EQ(n_written, padded_length);
  for (int i = 0; i < num_messages; ++i) {
    EXPECT_EQ(input_values[i], decrypted[i]);
  }
  for (int i = num_messages; i < padded_length; ++i) {
    EXPECT_EQ(decrypted_padded[i], 0);
  }

  // Check that the padding is not too long.
  constexpr int wrong_num_ciphertext_polynomials = 3;
  constexpr int wrong_padded_length =
      kNumCoeffs * num_packing * wrong_num_ciphertext_polynomials;
  constexpr int wrong_buffer_length = wrong_padded_length * 2;
  uint64_t wrong_decrypted_padded[wrong_buffer_length];
  SECAGG_ASSERT_OK(UnwrapFfiStatus(Decrypt(
      packing_base, num_packing, ciphertexts, key, params,
      rust::Slice(wrong_decrypted_padded, wrong_buffer_length), &n_written)));

  EXPECT_NE(n_written, wrong_padded_length);
}

TEST(KaheTest, Failures) {
  constexpr int num_packing = 8;
  constexpr uint64_t num_public_polynomials = 2;
  FfiStatus status;
  std::unique_ptr<std::string> public_seed;
  status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  KahePublicParametersWrapper params;
  status = CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  std::unique_ptr<std::string> private_seed;
  status = GenerateSingleThreadHkdfSeed(private_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  SingleThreadHkdfWrapper prng;
  status = CreateSingleThreadHkdf(ToRustSlice(*private_seed), prng);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  RnsPolynomialWrapper key;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(params, &prng, &key)));

  // Generate random messages that need 3 polynomials.
  constexpr int num_messages = kNumCoeffs * num_packing * 3;
  constexpr uint64_t packing_base = 2;
  std::vector<Integer> input_vec =
      rlwe::testing::SampleMessages(num_messages, packing_base);
  uint64_t input_values[num_messages];
  for (int i = 0; i < num_messages; ++i) {
    input_values[i] = input_vec[i];
  }

  // Check that encryption fails if we don't have enough public polynomials.
  RnsPolynomialVecWrapper vec_out;
  EXPECT_THAT(
      UnwrapFfiStatus(Encrypt(ToRustSlice(input_values), packing_base,
                              num_packing, key, params, &prng, &vec_out)),
      StatusIs(absl::StatusCode::kInvalidArgument));

  // Check failures on invalid pointers or wrappers
  KahePublicParametersWrapper bad_params = {.ptr = nullptr};
  EXPECT_THAT(UnwrapFfiStatus(Encrypt(
                  rust::Slice<const uint64_t>(input_values,
                                              2 * kNumCoeffs * num_packing),
                  packing_base, num_packing, key, bad_params, &prng, &vec_out)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  constexpr uint64_t buffer_length =
      2 * kNumCoeffs * num_packing;  // Room for 2 plaintext polynomials.
  uint64_t decrypted_long[buffer_length] = {};
  uint64_t n_written;
  vec_out.ptr = nullptr;
  EXPECT_THAT(UnwrapFfiStatus(Decrypt(
                  packing_base, num_packing, vec_out, key, params,
                  rust::Slice(decrypted_long, buffer_length), &n_written)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Also check keygen and parameters.
  RnsPolynomialWrapper key_out;
  EXPECT_THAT(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(bad_params, &prng, &key_out)),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(UnwrapFfiStatus(CreateKahePublicParametersWrapper(
                  kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
                  ToRustSlice(*public_seed), nullptr)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KaheTest, AddInPlacePolynomial) {
  constexpr uint64_t num_public_polynomials = 1;
  FfiStatus status;
  std::unique_ptr<std::string> public_seed;
  status = GenerateSingleThreadHkdfSeed(public_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  KahePublicParametersWrapper params;
  status = CreateKahePublicParametersWrapper(
      kLogN, kLogT, ToRustSlice(kQs), num_public_polynomials,
      ToRustSlice(*public_seed), &params);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  auto moduli = CreateModuliWrapperFromKaheParams(params);

  std::unique_ptr<std::string> private_seed;
  status = GenerateSingleThreadHkdfSeed(private_seed);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));
  SingleThreadHkdfWrapper prng;
  status = CreateSingleThreadHkdf(ToRustSlice(*private_seed), prng);
  SECAGG_ASSERT_OK(UnwrapFfiStatus(status));

  // Generate two keys.
  RnsPolynomialWrapper key_1;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(params, &prng, &key_1)));
  RnsPolynomialWrapper key_2;
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(GenerateSecretKeyWrapper(params, &prng, &key_2)));

  // Sample two messages and encrypt them.
  constexpr int num_messages = 10;
  constexpr uint64_t packing_base = 10;
  constexpr uint64_t input_domain =
      packing_base / 2;  // 2 inputs should fit in the base.
  constexpr int num_packing = 3;
  std::vector<Integer> input_values_1 =
      rlwe::testing::SampleMessages(num_messages, input_domain);
  RnsPolynomialVecWrapper ciphertexts_1;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(Encrypt(ToRustSlice(input_values_1),
                                           packing_base, num_packing, key_1,
                                           params, &prng, &ciphertexts_1)));
  std::vector<Integer> input_values_2 =
      rlwe::testing::SampleMessages(num_messages, input_domain);
  RnsPolynomialVecWrapper ciphertexts_2;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(Encrypt(ToRustSlice(input_values_2),
                                           packing_base, num_packing, key_2,
                                           params, &prng, &ciphertexts_2)));

  // Check that we can add keys (single polynomials) correctly.
  SECAGG_ASSERT_OK_AND_ASSIGN(auto manual_sum_copy,
                              key_1.ptr->Add(*key_2.ptr, params.ptr->moduli));
  SECAGG_ASSERT_OK(UnwrapFfiStatus(AddInPlace(moduli, &key_1, &key_2)));
  ASSERT_EQ(manual_sum_copy, *key_2.ptr);

  // Check that we can add vectors of polynomials.
  SECAGG_ASSERT_OK_AND_ASSIGN(
      manual_sum_copy, ciphertexts_1.ptr->at(0).Add(ciphertexts_2.ptr->at(0),
                                                    params.ptr->moduli));
  SECAGG_ASSERT_OK(
      UnwrapFfiStatus(AddInPlaceVec(moduli, &ciphertexts_1, &ciphertexts_2)));
  ASSERT_EQ(manual_sum_copy, ciphertexts_2.ptr->at(0));

  // Check homomorphism.
  uint64_t decrypted[num_messages];
  uint64_t n_written;
  SECAGG_ASSERT_OK(UnwrapFfiStatus(
      Decrypt(packing_base, num_packing, ciphertexts_2, key_2, params,
              rust::Slice(decrypted, num_messages), &n_written)));
  for (int i = 0; i < num_messages; ++i) {
    EXPECT_EQ(input_values_1[i] + input_values_2[i], decrypted[i]);
  }
}

}  // namespace
}  // namespace secure_aggregation
