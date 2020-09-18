/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRIVATE_ANALYTICS_PRIO_RANDOMIZED_RESPONSE_H_
#define PRIVATE_ANALYTICS_PRIO_RANDOMIZED_RESPONSE_H_

#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "prio/proto/algorithm_parameters.pb.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {

// This randomizer can be use to create randomized responses in [minimum,
// maximum] with bias = 1 / (1 + exp(epsilon)).
class Randomizer {
 public:
  // Create a randomizer: this factory function can fail with an invalid
  // argument error if epsilon < 0 or if hamming_weight is > bins.
  static absl::StatusOr<Randomizer> Create(
      const proto::PrioAlgorithmParameters& algorithm_parameters);

  // Randomize the span `bins`. If algorithm parameters contains the
  // hamming_weight field, the input will be replaced with a random
  // "hamming_weight"-hot vector with probability 1/(1+e^epsilon). Otherwise,
  // each entry of the input will independently be replaced with a random bit
  // with probability 1/(1+e^epsilon).
  //
  // Assumes that the structure of the input has already been verified (correct
  // length, inputs in the correct range, correct hamming weight if applicable).
  absl::StatusOr<std::vector<FieldElement>> RandomizeResponse(
      const absl::Span<const FieldElement> input);

 private:
  explicit Randomizer(
      const proto::PrioAlgorithmParameters& algorithm_parameters)
      : algorithm_parameters_(algorithm_parameters) {}
  proto::PrioAlgorithmParameters algorithm_parameters_;
};

}  // namespace prio
}  // namespace private_statistics

#endif  // PRIVATE_ANALYTICS_PRIO_RANDOMIZED_RESPONSE_H_
