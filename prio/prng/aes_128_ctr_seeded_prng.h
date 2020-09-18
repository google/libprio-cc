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

#ifndef PRIVATE_ANALYTICS_PRIO_PRNG_AES_128_CTR_SEEDED_PRNG_H_
#define PRIVATE_ANALYTICS_PRIO_PRNG_AES_128_CTR_SEEDED_PRNG_H_

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "prio/constants.h"
#include "prio/prng/seeded_prng.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {

// A legacy SeededPrng based on AES128 using CTR mode. This is a non-standard
// PRNG that we implement for exact compatibility with an existing external Prio
// implementation.
class Aes128CtrSeededPrng : public SeededPrng {
 public:
  Aes128CtrSeededPrng() = default;

  // Size of an AES128 key+nonce, in bytes.
  static size_t SeedSize();

  // Returns a cryptographically random string of SeedSize() bytes.
  absl::StatusOr<std::string> GenerateSeed() override;

  // Returns "num_elements" pseudorandomly chosen FieldElements using rejection
  // sampling. Randomness is generated using an AES128-CTR based PRNG seeded
  // with the supplied seed.
  //
  // Fails with INVALID_ARGUMENT if "seed" is not SeedSize() bytes long.
  absl::StatusOr<std::vector<FieldElement>> GetRandomFieldElementsFromSeed(
      absl::string_view seed, size_t num_elements) override;
};
}  // namespace prio
}  // namespace private_statistics

#endif  // PRIVATE_ANALYTICS_PRIO_PRNG_AES_128_CTR_SEEDED_PRNG_H_
