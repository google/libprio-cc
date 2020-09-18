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

#include "prio/prng/aes_128_ctr_seeded_prng.h"

#include <cstdint>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/rand.h>
#include "prio/testing/status_matchers.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {
namespace {

TEST(SeededPrngTest, SeedHasCorrectSize) {
  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed,
                            Aes128CtrSeededPrng().GenerateSeed());
  EXPECT_EQ(seed.size(), Aes128CtrSeededPrng::SeedSize());
}

TEST(SeededPrngTest, DifferentSeedsAreGenerated) {
  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed1,
                            Aes128CtrSeededPrng().GenerateSeed());
  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed2,
                            Aes128CtrSeededPrng().GenerateSeed());

  EXPECT_NE(seed1, seed2);
}

TEST(SeededPrngGetRandomFieldElementsTest, FailsOnWrongSizeKey) {
  size_t num_elements = 100;

  EXPECT_FALSE(
      Aes128CtrSeededPrng()
          .GetRandomFieldElementsFromSeed("wrong_seed_size", num_elements)
          .ok());
}

TEST(SeededPrngGetRandomFieldElementsTest, OutputIsDeterministic) {
  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed,
                            Aes128CtrSeededPrng().GenerateSeed());
  size_t num_elements = 100;

  PRIO_ASSERT_OK_AND_ASSIGN(
      std::vector<FieldElement> output1,
      Aes128CtrSeededPrng().GetRandomFieldElementsFromSeed(seed, num_elements));
  PRIO_ASSERT_OK_AND_ASSIGN(
      std::vector<FieldElement> output2,
      Aes128CtrSeededPrng().GetRandomFieldElementsFromSeed(seed, num_elements));

  EXPECT_EQ(output1, output2);
}

TEST(SeededPrngGetRandomFieldElementsTest, DifferentSeedsGiveDifferentOutputs) {
  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed1,
                            Aes128CtrSeededPrng().GenerateSeed());
  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed2,
                            Aes128CtrSeededPrng().GenerateSeed());
  size_t num_elements = 100;

  PRIO_ASSERT_OK_AND_ASSIGN(
      std::vector<FieldElement> output1,
      Aes128CtrSeededPrng().GetRandomFieldElementsFromSeed(seed1,
                                                           num_elements));
  PRIO_ASSERT_OK_AND_ASSIGN(
      std::vector<FieldElement> output2,
      Aes128CtrSeededPrng().GetRandomFieldElementsFromSeed(seed2,
                                                           num_elements));

  EXPECT_NE(output1, output2);
}

TEST(SeededPrngGetRandomFieldElementsTest, SucceedsOnLength0) {
  PRIO_ASSERT_OK_AND_ASSIGN(std::string seed,
                            Aes128CtrSeededPrng().GenerateSeed());

  PRIO_ASSERT_OK_AND_ASSIGN(
      std::vector<FieldElement> output,
      Aes128CtrSeededPrng().GetRandomFieldElementsFromSeed(seed, 0));
  EXPECT_EQ(output, std::vector<FieldElement>({}));
}

TEST(SeededPrngGetRandomFieldElementsTest, FixedSeed) {
  const size_t num_elements = 32;
  const std::vector<uint8_t> fixed_seed = {
      0xcd, 0x85, 0x5b, 0xd4, 0x86, 0x48, 0xa4, 0xce, 0x52, 0x5c, 0x36,
      0xee, 0x5a, 0x71, 0xf3, 0x0f, 0x66, 0x80, 0xd3, 0x67, 0x53, 0x9a,
      0x39, 0x6f, 0x12, 0x2f, 0xad, 0x94, 0x4d, 0x34, 0xcb, 0x58};
  const std::vector<FieldElement> reference(
      {0xd0056ec5, 0xe23f9c52, 0x47e4ddb4, 0xbe5dacf6, 0x4b130aba, 0x530c7a90,
       0xe8fc4ee5, 0xb0569cb7, 0x7774cd3c, 0x7f24e6a5, 0xcc82355d, 0xc41f4f13,
       0x67fe193c, 0xc94d63a4, 0x5d7b474c, 0xcc5c9f5f, 0xe368e1d5, 0x020fa0cf,
       0x9e96aa2a, 0xe924137d, 0xfa026ab9, 0x8ebca0cc, 0x26fc58a5, 0x10a7b173,
       0xb9c97291, 0x53ef0e28, 0x069cfb8e, 0xe9383cae, 0xacb8b748, 0x6f5b9d49,
       0x887d061b, 0x86db0c58});

  PRIO_ASSERT_OK_AND_ASSIGN(
      std::vector<FieldElement> output,
      Aes128CtrSeededPrng().GetRandomFieldElementsFromSeed(
          std::string(fixed_seed.begin(), fixed_seed.end()), num_elements));

  EXPECT_EQ(output.size(), num_elements);
  for (size_t i = 0; i < num_elements; i++) {
    EXPECT_EQ(output[i], reference[i]);
  }
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
