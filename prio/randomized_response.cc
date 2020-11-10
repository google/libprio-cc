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
#include <cstdint>
#include <cstdlib>
#include <limits>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include <openssl/rand.h>
#include "prio/finite_field.h"
#include "prio/status_macros.h"
#include "prio/types.h"
#include "prio/util.h"

namespace private_statistics {
namespace prio {

namespace {
using proto::PrioAlgorithmParameters;

// Flips a biased coin: returns true with probability "bias", and false
// otherwise. Returns false is bias < 0 and true if bias > 1.
bool CoinFlip(double bias) {
  if (bias < 0) {
    return false;  // Any number in [0, 1] is larger than bias.
  }
  if (bias > 1) {
    return true;  // Any number in [0, 1] is smaller than bias.
  }
  // We generate a random between [0, 1] using BoringSSL. We first generate a
  // random 32-bit integer, and divide it by 2^32-1.
  uint32_t rand_int;
  RAND_bytes(reinterpret_cast<uint8_t*>(&rand_int), sizeof(rand_int));
  double rand_double =
      static_cast<double>(rand_int) / std::numeric_limits<uint32_t>::max();
  return rand_double < bias;
}

// Returns a random value in [0,n).
size_t SampleBetween0AndN(size_t n) {
  size_t mask = internal::NextPowerTwoMinusOne<size_t>(n);
  size_t value = std::numeric_limits<size_t>::max();
  while (value >= n) {
    RAND_bytes(reinterpret_cast<uint8_t*>(&value), sizeof(size_t));
    value &= mask;
  }
  return value;
}

// Returns a random k-hot vector of the specified length.
std::vector<FieldElement> SampleKHotVector(size_t k, size_t length) {
  if (k >= length) {
    return std::vector<FieldElement>(length, 1);
  }

  std::vector<FieldElement> output(length, 0);

  for (size_t i = 0; i < k; i++) {
    // Find a random index that is not already set to 1.
    size_t index = SampleBetween0AndN(length);
    while (output[index] == 1) {
      index = SampleBetween0AndN(length);
    }
    output[index] = 1;
  }

  return output;
}

}  // namespace

absl::StatusOr<Randomizer> Randomizer::Create(
    const PrioAlgorithmParameters& algorithm_parameters) {
  // Check if the value of bins is specified and valid.
  if (!algorithm_parameters.has_bins()) {
    return absl::InvalidArgumentError(
        "Randomizer::Create: The number of bins is not specified.");
  } else if (algorithm_parameters.bins() <= 0) {
    return absl::InvalidArgumentError(
        "Randomizer::Create:The number of bins cannot be non-positive.");
  }

  // Check if the value of epsilon is valid. A valid epsilon also guarantees
  // that the bias is in [0,1).
  if (algorithm_parameters.epsilon() < 0) {
    return absl::InvalidArgumentError(
        "Randomizer::Create: epsilon cannot be negative.");
  }

  // Check if hamming weight is specified, and if so, if it is valid.
  if (algorithm_parameters.has_hamming_weight()) {
    if (algorithm_parameters.hamming_weight() <= 0 ||
        algorithm_parameters.hamming_weight() >= algorithm_parameters.bins()) {
      return absl::InvalidArgumentError(
          "Randomizer::Create: The hamming weight has to be in the range (0, "
          "bins).");
    }
  }

  return Randomizer(algorithm_parameters);
}

absl::StatusOr<std::vector<FieldElement>> Randomizer::RandomizeResponse(
    const absl::Span<const FieldElement> input) {
  if (input.size() != static_cast<size_t>(algorithm_parameters_.bins())) {
    return absl::InvalidArgumentError(
        "Randomizer::RandomizeResponse: input is not of the size specified by "
        "the algorithm parameters.");
  }

  double bias = 2.0 / (1.0 + std::exp(algorithm_parameters_.epsilon()));

  if (algorithm_parameters_.has_hamming_weight()) {
    // We generate another random "hamming_weight"-hot vector with probability
    // bias.
    if (CoinFlip(bias)) {
      return SampleKHotVector(
          static_cast<size_t>(algorithm_parameters_.hamming_weight()),
          static_cast<size_t>(algorithm_parameters_.bins()));
    } else {
      return std::vector<FieldElement>(input.begin(), input.end());
    }
  } else {
    // We randomize each element individually with probability bias.
    std::vector<FieldElement> output =
        std::vector<FieldElement>(input.begin(), input.end());
    for (size_t i = 0; i < input.size(); i++) {
      if (CoinFlip(bias)) {
        PRIO_ASSIGN_OR_RETURN(output[i], GenerateRandomFieldElement(0, 1));
      }
    }
    return output;
  }
}

}  // namespace prio
}  // namespace private_statistics
