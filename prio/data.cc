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

#include "prio/data.h"

#include "absl/status/status.h"
#include "prio/finite_field.h"

namespace private_statistics {
namespace prio {

bool PrioDataAndProofShare::operator==(
    const PrioDataAndProofShare& other) const {
  return data_share == other.data_share && f_0_share == other.f_0_share &&
         g_0_share == other.g_0_share && h_0_share == other.h_0_share &&
         h_share_packed == other.h_share_packed;
}

bool PrioDataAndProofShare::operator!=(
    const PrioDataAndProofShare& other) const {
  return !(*this == other);
}

absl::Status PrioDataAndProofShare::SubInPlace(
    const PrioDataAndProofShare& other) {
  // Check the sizes.
  if (data_share.size() != other.data_share.size() ||
      h_share_packed.size() != other.h_share_packed.size()) {
    return absl::InvalidArgumentError(
        "The size of the vectors in the elements are not the same.");
  }
  // Subtract the elements component-wise.
  for (size_t i = 0; i < data_share.size(); i++) {
    data_share[i] = SubMod(data_share[i], other.data_share[i]);
  }
  f_0_share = SubMod(f_0_share, other.f_0_share);
  g_0_share = SubMod(g_0_share, other.g_0_share);
  h_0_share = SubMod(h_0_share, other.h_0_share);
  for (size_t i = 0; i < h_share_packed.size(); i++) {
    h_share_packed[i] = SubMod(h_share_packed[i], other.h_share_packed[i]);
  }
  return absl::OkStatus();
}

}  // namespace prio
}  // namespace private_statistics
