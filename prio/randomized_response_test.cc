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

#include "prio/randomized_response.h"

#include <cmath>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "prio/constants.h"
#include "prio/finite_field.h"
#include "prio/proto/algorithm_parameters.pb.h"
#include "prio/testing/status_matchers.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {
namespace {

using proto::PrioAlgorithmParameters;
using ::testing::HasSubstr;
using testing::StatusIs;

const int32_t kNumBins = 10;

PrioAlgorithmParameters GetDefaultAlgorithmParameters() {
  PrioAlgorithmParameters algorithm_parameters;
  algorithm_parameters.set_bins(kNumBins);
  // All other entries are defaults/ not set.
  return algorithm_parameters;
}

TEST(RandomizerTest, WorksWithDefaultRandomizationParameters) {
  PRIO_ASSERT_OK_AND_ASSIGN(
      auto randomizer, Randomizer::Create(GetDefaultAlgorithmParameters()));
  std::vector<FieldElement> input(kNumBins, 0);
  PRIO_EXPECT_OK(randomizer.RandomizeResponse(input));
}

// Test that epsilon is >= 0.
TEST(RandomizerTest, EpsilonMustBeNonNegative) {
  PrioAlgorithmParameters algorithm_parameters =
      GetDefaultAlgorithmParameters();
  // epsilon < 0 yields an error.
  algorithm_parameters.set_epsilon(-1.0);
  EXPECT_THAT(
      Randomizer::Create(algorithm_parameters),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("epsilon")));
  // epsilon >= 0 works.
  algorithm_parameters.set_epsilon(0.0);
  PRIO_EXPECT_OK(Randomizer::Create(algorithm_parameters));
  algorithm_parameters.set_epsilon(1.0);
  PRIO_EXPECT_OK(Randomizer::Create(algorithm_parameters));
}

// Randomized response stays within bounds.
TEST(ElementWiseRandomizedResponseTest, OutputStaysWithinBounds) {
  const int num_bins = 1000;
  const double epsilon = 0;  // The bias will be 1, i.e., the output should be
                             // randomized with probability 1.
  PrioAlgorithmParameters algorithm_parameters =
      GetDefaultAlgorithmParameters();
  algorithm_parameters.set_bins(num_bins);
  algorithm_parameters.set_epsilon(epsilon);

  // Create the randomizer.
  PRIO_ASSERT_OK_AND_ASSIGN(auto randomizer,
                            Randomizer::Create(algorithm_parameters));

  // Sample a uniformly random set of inputs element.
  std::vector<FieldElement> input;
  input.reserve(num_bins);
  for (int i = 0; i < num_bins; i++) {
    PRIO_ASSERT_OK_AND_ASSIGN(
        auto element,
        private_statistics::prio::GenerateRandomFieldElement(0, 1));
    input.push_back(element);
  }

  // Randomize the input.
  PRIO_ASSERT_OK_AND_ASSIGN(std::vector<FieldElement> output,
                            randomizer.RandomizeResponse(input));

  // Check output length.
  EXPECT_EQ(output.size(), input.size());

  // Check bounds
  for (int i = 0; i < num_bins; i++) {
    EXPECT_LE(output[i], 1);
    EXPECT_GE(output[i], 0);
  }
}

TEST(ElementWiseRandomizedResponseTest, OutputHasRightDistribution) {
  const int num_bins = 1000;
  for (double epsilon : {0.5, 1.0, 12.0}) {
    PrioAlgorithmParameters algorithm_parameters =
        GetDefaultAlgorithmParameters();
    algorithm_parameters.set_bins(num_bins);
    algorithm_parameters.set_epsilon(epsilon);

    // The bias will be 2/(1+exp(epsilon)), i.e., so the output should be
    // randomized with that probability. We generate num_bins samples, and
    // check that the result is smaller than 6 standard deviations away
    // from the mean.
    // We estimate the failure probability by using the central limit theorem,
    // for which the confidence interval is [mean - 6*sigma, mean + 6*sigma]
    // with probability ~ 1 - 2^-29.
    // https://en.wikipedia.org/wiki/68%E2%80%9395%E2%80%9399.7_rule
    double bias = 2.0 / (1.0 + std::exp(epsilon));
    double stddev = std::sqrt(num_bins * bias * (1 - bias));
    // Create the randomizer.
    PRIO_ASSERT_OK_AND_ASSIGN(auto randomizer,
                              Randomizer::Create(algorithm_parameters));

    // Sample a uniformly random set of inputs element.
    std::vector<FieldElement> input;
    input.reserve(num_bins);
    for (int i = 0; i < num_bins; i++) {
      PRIO_ASSERT_OK_AND_ASSIGN(
          auto element,
          private_statistics::prio::GenerateRandomFieldElement(0, 1));
      input.push_back(element);
    }

    // Randomize the input.
    PRIO_ASSERT_OK_AND_ASSIGN(std::vector<FieldElement> output,
                              randomizer.RandomizeResponse(input));

    // Count equal entries.
    double num_equal_entries = 0;
    for (int i = 0; i < num_bins; i++) {
      if (input[i] == output[i]) {
        num_equal_entries++;
      }
    }

    // Compute the expected number of equal entries:
    // - with probability 1-bias, the output is unreplaced.
    // - with probability bias * 1 / (maximum - minimum + 1),
    //   the random replacement of the output will actually be the same as
    //   the corresponding input.
    //
    // Note we use minimum = 0 and maximum = 1, therefore we multiply the bias
    // by 0.5
    double expected_equal_entries = num_bins * (1.0 - bias + bias * 0.5);

    EXPECT_LE(abs(expected_equal_entries - num_equal_entries), 6 * stddev);
  }
}

TEST(KHotRandomizedResponseTest, OutputIsOneHot) {
  const double epsilon = 0;  // The bias will be 1, i.e., the output should be
                             // randomized with probability 1.
  int32_t hamming_weight = 8;

  PrioAlgorithmParameters algorithm_parameters =
      GetDefaultAlgorithmParameters();
  algorithm_parameters.set_epsilon(epsilon);
  algorithm_parameters.set_hamming_weight(hamming_weight);

  // Create the randomizer.
  PRIO_ASSERT_OK_AND_ASSIGN(auto randomizer,
                            Randomizer::Create(algorithm_parameters));

  std::vector<FieldElement> input(kNumBins, 0);
  for (int32_t i = 0; i < hamming_weight; i++) {
    input[i] = 1;
  }

  // Randomize the input.
  PRIO_ASSERT_OK_AND_ASSIGN(std::vector<FieldElement> output,
                            randomizer.RandomizeResponse(input));

  // Check output length.
  ASSERT_EQ(output.size(), input.size());

  // Check output is hamming_weight-hot
  int32_t ones_encountered = 0;
  for (int32_t i = 0; i < kNumBins; i++) {
    if (output[i] != 0) {
      ones_encountered++;
    }
  }

  EXPECT_EQ(ones_encountered, hamming_weight);
}

TEST(KHotRandomizedResponseTest, OutputHasRightDistributionForOneHot) {
  const int num_samples = 1000;

  std::vector<FieldElement> input(kNumBins, 0);
  input[0] = 1;

  for (double epsilon :
       {0.5, 1.0, 12.0}) {  // We will try several epsilon values.
    PrioAlgorithmParameters algorithm_parameters =
        GetDefaultAlgorithmParameters();
    algorithm_parameters.set_epsilon(epsilon);
    algorithm_parameters.set_hamming_weight(1);

    // Create the randomizer.
    PRIO_ASSERT_OK_AND_ASSIGN(auto randomizer,
                              Randomizer::Create(algorithm_parameters));

    // The bias will be 2/(1+exp(epsilon)), i.e., so the output should be
    // randomized with that probability. We generate num_samples samples, and
    // check that the result is smaller than 6 standard deviations away
    // from the mean.
    // We estimate the failure probability by using the central limit theorem,
    // for which the confidence interval is [mean - 6*sigma, mean + 6*sigma]
    // with probability ~ 1 - 2^-29.
    // https://en.wikipedia.org/wiki/68%E2%80%9395%E2%80%9399.7_rule
    double bias = 2.0 / (1.0 + std::exp(epsilon));
    double stddev = std::sqrt(num_samples * bias * (1 - bias));

    double num_equal_samples = 0;
    for (int i = 0; i < num_samples; i++) {
      // Randomize the input.
      PRIO_ASSERT_OK_AND_ASSIGN(std::vector<FieldElement> output,
                                randomizer.RandomizeResponse(input));
      if (input == output) {
        num_equal_samples++;
      }
    }

    // Compute the expected number of equal entries:
    // - with probability 1-bias, the output is unreplaced.
    // - with probability bias * 1 / (num_bins),
    //   the random replacement of the output will actually be the same as
    //   the input.
    double expected_equal_samples =
        num_samples * (1.0 - bias + bias * 1.0 / kNumBins);

    EXPECT_LE(abs(expected_equal_samples - num_equal_samples), 6 * stddev);
  }
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
