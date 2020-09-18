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

#include "prio/finite_field.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include "absl/status/status.h"
#include <openssl/rand.h>
#include "prio/constants.h"
#include "prio/util.h"

namespace private_statistics {
namespace prio {

// Implements exponentiation using repeated exponentiation.
FieldElement ExpMod(FieldElement base, int exp) {
  // If the exponent is negative, compute the inverse of the base.
  if (exp < 0) {
    base = InvMod(base);
  }

  // Look at the absolute value of the exponent.
  exp = abs(exp);

  FieldElement result = 1;
  for (size_t i = 0; i < sizeof(exp) * 8; i++) {
    // Output MulMod(result, base) if exp&1 == 1, and result otherwise.
    FieldElement mask = static_cast<FieldElement>(-(exp & 1));
    result ^= mask & (MulMod(result, base) ^ result);
    exp >>= 1;
    base = MulMod(base, base);
  }
  return result;
}

// Implements exponentiation using extended Euclidean algorithm.
FieldElement InvMod(const FieldElement a) {
  int32_t x0 = 0;
  int32_t x1 = 1;
  FieldElement a1 = a;
  FieldElement a2 = kPrioModulus;
  FieldElement q = 0;

  while (a2 != 0) {
    FieldElement a0 = a1;
    int32_t x2 = x0 - static_cast<int32_t>(q) * x1;
    x0 = x1;
    x1 = x2;
    a1 = a2;
    q = a0 / a1;
    a2 = a0 - q * a1;
  }

  if (x1 < 0) {
    return (kPrioModulus + static_cast<FieldElement>(x1));
  } else {
    return static_cast<FieldElement>(x1);
  }
}

absl::StatusOr<FieldElement> GenerateRandomFieldElement(FieldElement minimum,
                                                        FieldElement maximum) {
  if (minimum > maximum) {
    return absl::InvalidArgumentError("The minimum is larger than the maximum");
  } else if (minimum == maximum) {
    return minimum;
  }
  // LINT.IfChange
  uint32_t mask = internal::NextPowerTwoMinusOne<uint32_t>(maximum - minimum);
  uint32_t value = std::numeric_limits<uint32_t>::max();
  while (value > maximum - minimum) {
    RAND_bytes(reinterpret_cast<uint8_t*>(&value), sizeof(uint32_t));
    value &= mask;
  }
  // LINT.ThenChange(//depot/google3/third_party/private_statistics/prio/types.h,
  // //depot/google3/third_party/private_statistics/prio/finite_field.h)
  return minimum + value;
}

absl::StatusOr<std::vector<FieldElement>> ConvertToFieldElements(
    absl::string_view input_string) {
  if (input_string.size() % sizeof(FieldElement) != 0) {
    return absl::InvalidArgumentError(
        "The string size is not a multiple of sizeof(FieldElement).");
  }

  size_t num_elements = input_string.size() / sizeof(FieldElement);

  std::vector<FieldElement> output;
  output.reserve(num_elements);

  const FieldElement* current_position =
      reinterpret_cast<const FieldElement*>(input_string.data());

  for (size_t i = 0; i < num_elements; i++) {
    output.push_back(*current_position % kPrioModulus);
    current_position++;
  }

  return output;
}

}  // namespace prio
}  // namespace private_statistics
