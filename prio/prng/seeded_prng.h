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

#ifndef LIBPRIO_CC_PRIO_PRNG_SEEDED_PRNG_H_
#define LIBPRIO_CC_PRIO_PRNG_SEEDED_PRNG_H_

#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "prio/constants.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {

// An interface defining a seeded PRNG.
class SeededPrng {
 public:
  virtual ~SeededPrng() = default;

  // Implementations should return a freshly generated seed of the correct size.
  virtual absl::StatusOr<std::string> GenerateSeed() = 0;

  // Implementations should return "num_elements" pseudorandomly chosen
  // FieldElements. If the same seed and length are provided, the output should
  // be the same.
  virtual absl::StatusOr<std::vector<FieldElement>>
  GetRandomFieldElementsFromSeed(absl::string_view seed,
                                 size_t num_elements) = 0;
};

}  // namespace prio
}  // namespace private_statistics

#endif  // LIBPRIO_CC_PRIO_PRNG_SEEDED_PRNG_H_
