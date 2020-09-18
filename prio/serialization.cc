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

#include "prio/serialization.h"

#include <cstddef>
#include <iterator>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "prio/finite_field.h"
#include "prio/prng/aes_128_ctr_seeded_prng.h"
#include "prio/prng/seeded_prng.h"
#include "prio/status_macros.h"
#include "prio/types.h"
#include "prio/util.h"

namespace private_statistics {
namespace prio {

namespace {
using proto::PrioAlgorithmParameters;
}

absl::Status IsShareConsistentWithParams(
    const PrioDataAndProofShare& data_and_proof_share,
    const PrioAlgorithmParameters& parameters) {
  // The size of the data vector.
  size_t num_elements_in_data_share = parameters.bins();
  // The number of points h should be evaluated at.
  PRIO_ASSIGN_OR_RETURN(
      size_t num_elements_in_h_share,
      internal::MinSizePolynomial(num_elements_in_data_share));

  if (data_and_proof_share.data_share.size() != num_elements_in_data_share) {
    return absl::InvalidArgumentError(
        "Data share size is different from supplied parameters.");
  }

  if (data_and_proof_share.h_share_packed.size() != num_elements_in_h_share) {
    return absl::InvalidArgumentError(
        "h_share_packed size is different from that deduced from the supplied "
        "parameters.");
  }

  return absl::OkStatus();
}

absl::StatusOr<std::string> SerializeShare(
    const PrioDataAndProofShare& data_and_proof_share,
    const PrioAlgorithmParameters& parameters) {
  if (!internal::IsLittleEndian()) {
    return absl::UnimplementedError(
        "Serialization not supported on non-little-endian architectures");
  }

  PRIO_RETURN_IF_ERROR(
      IsShareConsistentWithParams(data_and_proof_share, parameters));

  PRIO_ASSIGN_OR_RETURN(size_t serialization_length_bytes,
                        internal::SerializationLengthBytes(parameters));

  std::vector<uint8_t> serialization(serialization_length_bytes, 0);

  FieldElement* current_position =
      reinterpret_cast<FieldElement*>(serialization.data());

  // Serialize data share.
  for (size_t i = 0; i < data_and_proof_share.data_share.size(); i++) {
    *current_position = data_and_proof_share.data_share[i];
    current_position++;
  }

  // Serialize evaluations of polynomials f,g,h at 0.
  *current_position = data_and_proof_share.f_0_share;
  current_position++;
  *current_position = data_and_proof_share.g_0_share;
  current_position++;
  *current_position = data_and_proof_share.h_0_share;
  current_position++;

  // Serialize packed h share.
  for (size_t i = 0; i < data_and_proof_share.h_share_packed.size(); i++) {
    *current_position = data_and_proof_share.h_share_packed[i];
    current_position++;
  }

  return std::string(std::make_move_iterator(serialization.begin()),
                     std::make_move_iterator(serialization.end()));
}

absl::StatusOr<PrioDataAndProofShare> ExpandToShare(
    absl::string_view seed, const PrioAlgorithmParameters& parameters,
    SeededPrng* prng) {
  PRIO_ASSIGN_OR_RETURN(size_t field_elements_in_share,
                        internal::FieldElementsInShare(parameters));
  PRIO_ASSIGN_OR_RETURN(
      std::vector<FieldElement> elements,
      prng->GetRandomFieldElementsFromSeed(seed, field_elements_in_share));

  size_t num_elements_in_data_share = parameters.bins();

  PrioDataAndProofShare expanded_share;
  expanded_share.data_share = std::vector<FieldElement>(
      std::make_move_iterator(elements.begin()),
      std::make_move_iterator(elements.begin() + num_elements_in_data_share));
  expanded_share.f_0_share = std::move(elements[num_elements_in_data_share]);
  expanded_share.g_0_share =
      std::move(elements[num_elements_in_data_share + 1]);
  expanded_share.h_0_share =
      std::move(elements[num_elements_in_data_share + 2]);
  expanded_share.h_share_packed = std::vector<FieldElement>(
      std::make_move_iterator(elements.begin() + num_elements_in_data_share +
                              3),
      std::make_move_iterator(elements.end()));

  return expanded_share;
}

// Deserializes the given string into a PrioDataAndProofShare.
absl::StatusOr<PrioDataAndProofShare> DeserializeShare(
    absl::string_view serialized_share,
    const PrioAlgorithmParameters& parameters) {
  if (!internal::IsLittleEndian()) {
    return absl::UnimplementedError(
        "Deserialization is not supported on non-little-endian architectures.");
  }

  PRIO_ASSIGN_OR_RETURN(size_t expected_serialization_length_bytes,
                        internal::SerializationLengthBytes(parameters));

  if (expected_serialization_length_bytes != serialized_share.size()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Serialized share has a length different from that "
                     "prescribed by the parameters: expected length: ",
                     expected_serialization_length_bytes,
                     ", length of provided share: ", serialized_share.size()));
  }

  PRIO_ASSIGN_OR_RETURN(std::vector<FieldElement> deserialized_elements,
                        ConvertToFieldElements(serialized_share));

  size_t num_elements_in_data_share = parameters.bins();

  PrioDataAndProofShare deserialized_share;
  deserialized_share.data_share = std::vector<FieldElement>(
      deserialized_elements.begin(),
      deserialized_elements.begin() + num_elements_in_data_share);
  deserialized_share.f_0_share =
      deserialized_elements[num_elements_in_data_share];
  deserialized_share.g_0_share =
      deserialized_elements[num_elements_in_data_share + 1];
  deserialized_share.h_0_share =
      deserialized_elements[num_elements_in_data_share + 2];
  deserialized_share.h_share_packed = std::vector<FieldElement>(
      deserialized_elements.begin() + num_elements_in_data_share + 3,
      deserialized_elements.end());

  return std::move(deserialized_share);
}

}  // namespace prio
}  // namespace private_statistics
