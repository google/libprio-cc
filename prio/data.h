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

#ifndef PRIVATE_ANALYTICS_PRIO_DATA_H_
#define PRIVATE_ANALYTICS_PRIO_DATA_H_

#include <stdint.h>

#include <vector>

#include "absl/status/statusor.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {

// Structure to hold a secret share of data, and the accompanying proof share.
// This structure is hardcoded to accommodate a proof that data_share is an
// additive share of a binary (and only binary) vector.
struct PrioDataAndProofShare {
  // The length of data_share is exactly the length of the underlying binary
  // data vector.
  std::vector<FieldElement> data_share;

  // Shares of evaluations of polynomials f, g, and h at the point 0.
  FieldElement f_0_share;
  FieldElement g_0_share;
  FieldElement h_0_share;

  // The packed encoding of the share of polynomial h. Prior to secret sharing,
  // h should be the product of f and g. The packing consists of evaluation of
  // the polynomial h at several points. The encodings drops the evaluations of
  // h at points that are expected to have value 0. h_share_packed should have
  // length equal to the nearest power of two greater than data_share.size().
  std::vector<FieldElement> h_share_packed;

  // Operators for equality.
  bool operator==(const PrioDataAndProofShare& other) const;
  bool operator!=(const PrioDataAndProofShare& other) const;

  // Subtraction of another share in place.
  absl::Status SubInPlace(const PrioDataAndProofShare& other);
};

}  // namespace prio
}  // namespace private_statistics

#endif  // PRIVATE_ANALYTICS_PRIO_DATA_H_
