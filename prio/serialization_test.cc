// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "prio/serialization.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "prio/constants.h"
#include "prio/finite_field.h"
#include "prio/prng/aes_128_ctr_seeded_prng.h"
#include "prio/testing/status_matchers.h"
#include "prio/types.h"
#include "prio/util.h"

namespace private_statistics {
namespace prio {
namespace {

using proto::PrioAlgorithmParameters;
using ::testing::HasSubstr;
using testing::StatusIs;

size_t kDimension = 16;

// Creates parameters with default values and given data dimension.
PrioAlgorithmParameters GetParameters(size_t dimension) {
  PrioAlgorithmParameters parameters;
  parameters.set_bins(dimension);
  return parameters;
}

// Creates a dummy share, with uniformly random FieldElements. Assumes default
// prime.
PrioDataAndProofShare GenerateDummyShare(
    const PrioAlgorithmParameters& parameters) {
  PrioDataAndProofShare result;

  size_t num_elements_in_data_share = parameters.bins();
  // The number of points h should be evaluated at.
  size_t num_elements_in_h_share =
      internal::NextPowerTwo(num_elements_in_data_share + 1).value();

  result.data_share.reserve(num_elements_in_data_share);
  result.h_share_packed.reserve(num_elements_in_h_share);

  for (size_t i = 0; i < num_elements_in_data_share; i++) {
    result.data_share.push_back(GenerateRandomFieldElement().value());
  }

  result.f_0_share = GenerateRandomFieldElement().value();
  result.g_0_share = GenerateRandomFieldElement().value();
  result.h_0_share = GenerateRandomFieldElement().value();

  for (size_t i = 0; i < num_elements_in_h_share; i++) {
    result.h_share_packed.push_back(GenerateRandomFieldElement().value());
  }

  return result;
}

TEST(IsShareConsistentWithParamsTest, SucceedsOnValidShare) {
  PrioAlgorithmParameters parameters = GetParameters(kDimension);
  PrioDataAndProofShare share = GenerateDummyShare(parameters);

  PRIO_EXPECT_OK(IsShareConsistentWithParams(share, parameters));
}

TEST(IsShareConsistentWithParamsTest, FailsOnInValidShare) {
  PrioAlgorithmParameters parameters = GetParameters(kDimension);
  PrioDataAndProofShare empty_share;  // empty vectors.

  EXPECT_THAT(IsShareConsistentWithParams(empty_share, parameters),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("share size is different")));
}

TEST(SerializationTest, EncodeAndDecodeResultsInSameShare) {
  PrioAlgorithmParameters parameters = GetParameters(kDimension);
  PrioDataAndProofShare share = GenerateDummyShare(parameters);

  PRIO_ASSERT_OK_AND_ASSIGN(std::string serialized_share,
                            SerializeShare(share, parameters));

  PRIO_ASSERT_OK_AND_ASSIGN(PrioDataAndProofShare deserialized_share,
                            DeserializeShare(serialized_share, parameters));

  EXPECT_EQ(share, deserialized_share);
}

TEST(SerializationTest, DeserializeFromSeedGivesValidShare) {
  PrioAlgorithmParameters parameters = GetParameters(kDimension);
  Aes128CtrSeededPrng prng;

  // Create a seed and expand to a share
  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed, prng.GenerateSeed());
  PRIO_ASSERT_OK_AND_ASSIGN(PrioDataAndProofShare share,
                            ExpandToShare(seed, parameters, &prng));

  PRIO_EXPECT_OK(IsShareConsistentWithParams(share, parameters));
}

TEST(SerializationTest, ExpandTwiceGivesSameShare) {
  PrioAlgorithmParameters parameters = GetParameters(kDimension);
  Aes128CtrSeededPrng prng;

  // Create a seed and expand to a share
  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed, prng.GenerateSeed());
  PRIO_ASSERT_OK_AND_ASSIGN(PrioDataAndProofShare first_deserialization,
                            ExpandToShare(seed, parameters, &prng));
  PRIO_ASSERT_OK_AND_ASSIGN(PrioDataAndProofShare second_deserialization,
                            ExpandToShare(seed, parameters, &prng));

  EXPECT_EQ(first_deserialization, second_deserialization);
}

TEST(SerializationTest, DifferentSeedsGiveDifferentShares) {
  PrioAlgorithmParameters parameters = GetParameters(kDimension);
  Aes128CtrSeededPrng prng;

  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed_1, prng.GenerateSeed());
  PRIO_ASSERT_OK_AND_ASSIGN(PrioDataAndProofShare share_1,
                            ExpandToShare(seed_1, parameters, &prng));

  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed_2, prng.GenerateSeed());
  PRIO_ASSERT_OK_AND_ASSIGN(PrioDataAndProofShare share_2,
                            ExpandToShare(seed_2, parameters, &prng));

  EXPECT_NE(share_1, share_2);
}

TEST(SerializationTest, DeserializationFailsOnWrongSizeString) {
  PrioAlgorithmParameters parameters = GetParameters(kDimension);
  PrioDataAndProofShare share = GenerateDummyShare(parameters);
  PRIO_ASSERT_OK_AND_ASSIGN(std::string valid_serialized_share,
                            SerializeShare(share, parameters));

  std::string too_short(valid_serialized_share.begin(),
                        valid_serialized_share.end() - 1);
  std::string too_long = valid_serialized_share + "extra";

  EXPECT_THAT(DeserializeShare(too_short, parameters),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("length different")));

  EXPECT_THAT(DeserializeShare(too_long, parameters),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("length different")));
}

// Check interoperability with
// https://github.com/abetterinternet/libprio-rs/blob/master/src/prng.rs
TEST(SecretSharingTest, Interoperability) {
  size_t num_bins = 7;
  PrioAlgorithmParameters parameters = GetParameters(num_bins);
  const std::vector<uint8_t> reference_seed = {
      0xcd, 0x85, 0x5b, 0xd4, 0x86, 0x48, 0xa4, 0xce, 0x52, 0x5c, 0x36,
      0xee, 0x5a, 0x71, 0xf3, 0x0f, 0x66, 0x80, 0xd3, 0x67, 0x53, 0x9a,
      0x39, 0x6f, 0x12, 0x2f, 0xad, 0x94, 0x4d, 0x34, 0xcb, 0x58};
  const PrioDataAndProofShare reference_share = {
      .data_share = {0xd0056ec5, 0xe23f9c52, 0x47e4ddb4, 0xbe5dacf6, 0x4b130aba,
                     0x530c7a90, 0xe8fc4ee5},
      .f_0_share = 0xb0569cb7,
      .g_0_share = 0x7774cd3c,
      .h_0_share = 0x7f24e6a5,
      .h_share_packed = {0xcc82355d, 0xc41f4f13, 0x67fe193c, 0xc94d63a4,
                         0x5d7b474c, 0xcc5c9f5f, 0xe368e1d5, 0x020fa0cf},
  };
  Aes128CtrSeededPrng prng;

  PRIO_ASSERT_OK_AND_ASSIGN(
      auto expanded_share,
      ExpandToShare(std::string(reference_seed.begin(), reference_seed.end()),
                    parameters, &prng));

  EXPECT_EQ(expanded_share, reference_share);
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
