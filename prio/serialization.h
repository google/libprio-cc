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

#ifndef PRIVATE_ANALYTICS_PRIO_SERIALIZATION_H_
#define PRIVATE_ANALYTICS_PRIO_SERIALIZATION_H_

#include "absl/status/statusor.h"
#include "prio/data.h"
#include "prio/prng/aes_128_ctr_seeded_prng.h"
#include "prio/prng/seeded_prng.h"
#include "prio/proto/algorithm_parameters.pb.h"

namespace private_statistics {
namespace prio {

// Returns OkStatus if a share is consistent with the given parameters, and a
// descriptive InvalidArgumentError otherwise.
absl::Status IsShareConsistentWithParams(
    const PrioDataAndProofShare& data_and_proof_share,
    const proto::PrioAlgorithmParameters& parameters);

// Serializes the given Prio data share and associated proof share.
//
// This function assumes that all other processing on the share has been
// completed (for example, masking by pseudorandom strings). This function
// should only be called for a share that were not directly generated from a
// PRNG seed. For PRNG seed shares, the seed itself should be used as the
// serialization.
//
// Fails if the parameters are inconsistent with the supplied share. Also fails
// on non-little-endian architectures.
absl::StatusOr<std::string> SerializeShare(
    const PrioDataAndProofShare& data_and_proof_share,
    const proto::PrioAlgorithmParameters& parameters);

// Expands the given seed into the secret share of the data and the
// corresponding proof share using the supplied PRNG. The
// PrioAlgorithmParameters are used to determine the length of the data share to
// generate.
//
// Fails if the seed is not consistent with the parameters/ PRNG.
absl::StatusOr<PrioDataAndProofShare> ExpandToShare(
    absl::string_view seed, const proto::PrioAlgorithmParameters& parameters,
    SeededPrng* prng);

// Deserializes the given string into a PrioDataAndProofShare. The
// PrioAlgorithmParameters are used to determine the length of the data share to
// retrieve and to verify correctness.
//
// Fails if the serialized_share is not consistent with the parameters.
absl::StatusOr<PrioDataAndProofShare> DeserializeShare(
    absl::string_view serialized_share,
    const proto::PrioAlgorithmParameters& parameters);

}  // namespace prio
}  // namespace private_statistics

#endif  // PRIVATE_ANALYTICS_PRIO_SERIALIZATION_H_
