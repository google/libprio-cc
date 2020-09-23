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

#ifndef LIBPRIO_CC_PRIO_UTIL_H_
#define LIBPRIO_CC_PRIO_UTIL_H_

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "prio/proto/algorithm_parameters.pb.h"
#include "prio/status_macros.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {
namespace internal {

using private_statistics::prio::proto::PrioAlgorithmParameters;

// Test for system endianness.
#ifdef ABSL_IS_LITTLE_ENDIAN
inline constexpr bool IsLittleEndian() { return true; }
#elif defined ABSL_IS_BIG_ENDIAN
inline constexpr bool IsLittleEndian() { return false; }
#endif /* ENDIAN */

// Return the value 2^j-1 >= value for the smallest possible j.
template <typename Uint>
Uint NextPowerTwoMinusOne(Uint value) {
  Uint mask = static_cast<Uint>(-1);
  while ((mask >> 1) >= value && mask != 0) {
    mask >>= 1;
  }
  return mask;
}

// Return the value 2^j >= value for the smallest possible j.
// Returns an error if 2^j does not fit into an Uint.
template <typename Uint>
absl::StatusOr<Uint> NextPowerTwo(Uint value) {
  for (size_t i = 0; i < sizeof(Uint) * 8; i++) {
    if (value <= static_cast<Uint>(1) << i) {
      return static_cast<Uint>(1) << i;
    }
  }

  // If the answer is maximal, there is only one possible `value` for which the
  // answer fits in an Uint.
  if (value == (static_cast<Uint>(1) << (sizeof(Uint) * 8 - 1))) {
    return value;
  } else {
    return absl::InvalidArgumentError(
        "The next power of two does not fit into an Uint.");
  }
}

// Returns the minimal size of a polynomial that allows to embed an input
// containing number_bins bins.
inline absl::StatusOr<size_t> MinSizePolynomial(size_t number_bins) {
  return NextPowerTwo<size_t>(number_bins + 1);
}

// Number of FieldElements in a PrioDataAndProofShare for the given
// PrioAlgorithmParameters.
inline absl::StatusOr<size_t> FieldElementsInShare(
    const PrioAlgorithmParameters& parameters) {
  // The size of the data vector.
  size_t num_elements_in_data_share = parameters.bins();

  // The number of points at which we evaluate h.
  PRIO_ASSIGN_OR_RETURN(size_t num_elements_in_h_share,
                        MinSizePolynomial(num_elements_in_data_share));

  // We need 3 more elements in order to hold shares of f_0, g_0 and h_0.
  return (num_elements_in_data_share + num_elements_in_h_share + 3);
}

// Size (in bytes) of serialized PrioDataAndProofShare given the
// PrioAlgorithmParameters.
inline absl::StatusOr<size_t> SerializationLengthBytes(
    const PrioAlgorithmParameters& parameters) {
  PRIO_ASSIGN_OR_RETURN(size_t num_elements_in_share,
                        FieldElementsInShare(parameters));
  return num_elements_in_share * sizeof(FieldElement);
}

}  // namespace internal
}  // namespace prio
}  // namespace private_statistics

#endif  // LIBPRIO_CC_PRIO_UTIL_H_
