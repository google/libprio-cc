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

#ifndef LIBPRIO_CC_PRIO_FINITE_FIELD_H_
#define LIBPRIO_CC_PRIO_FINITE_FIELD_H_

#include <vector>

#include "absl/status/statusor.h"
#include "prio/constants.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {

FieldElement ExpMod(FieldElement base, int exp);
FieldElement InvMod(FieldElement a);

static inline FieldElement SubMod(FieldElement a, FieldElement b) {
  if (a >= b) {
    return a - b;
  } else {
    return kPrioModulus - b + a;
  }
}

static inline FieldElement AddMod(FieldElement a, FieldElement b) {
  return SubMod(a, kPrioModulus - b);
}

static inline FieldElement MulMod(FieldElement a, FieldElement b) {
  uint64_t al = a;
  uint64_t bl = b;
  uint64_t p = al * bl;
  return p % kPrioModulus;
}

// Mod-multiplies n by the inverse of d.
static inline FieldElement DivMod(FieldElement n, FieldElement d) {
  return MulMod(n, InvMod(d));
}

// Generate a random field element. Returns an invalid argument error if minimum
// > maximum.
absl::StatusOr<FieldElement> GenerateRandomFieldElement(
    FieldElement minimum = 0, FieldElement maximum = kPrioModulus - 1);

// Extract FieldElements from the given string. Fails if the string is not a
// multiple of sizeof(FieldElement).
absl::StatusOr<std::vector<FieldElement>> ConvertToFieldElements(
    absl::string_view input_string);

}  // namespace prio
}  // namespace private_statistics

#endif  // LIBPRIO_CC_PRIO_FINITE_FIELD_H_
