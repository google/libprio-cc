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

#include "prio/testing/simplified_server.h"

#include <iterator>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "prio/types.h"
#include "prio/util.h"

namespace private_statistics {
namespace prio {
namespace testing {

namespace internal {

inline std::string Serialize(const std::vector<FieldElement>& input) {
  std::vector<uint8_t> serialization(input.size() * sizeof(FieldElement));
  FieldElement* current_position =
      reinterpret_cast<FieldElement*>(serialization.data());
  for (auto& e : input) {
    *current_position = e;
    current_position++;
  }
  return std::string(std::make_move_iterator(serialization.begin()),
                     std::make_move_iterator(serialization.end()));
}

inline absl::StatusOr<std::vector<FieldElement>> Deserialize(
    absl::string_view input) {
  if (input.size() % sizeof(FieldElement) != 0) {
    return absl::InvalidArgumentError(
        "The input does not thave the right length");
  }
  std::vector<FieldElement> out;
  out.reserve(input.size() / sizeof(FieldElement));
  for (size_t i = 0; i < input.size() / sizeof(FieldElement); i++) {
    const FieldElement* current_position =
        reinterpret_cast<const FieldElement*>(input.data() +
                                              i * sizeof(FieldElement));
    out.push_back(*current_position);
    current_position++;
  }
  return out;
}

}  // namespace internal

auto SimplifiedServer::ProcessBatch(const proto::PrioDataShareBatch& batch)
    -> absl::StatusOr<prio::proto::PrioValidityShareBatch> {
  proto::PrioValidityShareBatch validity_batch;

  PRIO_ASSIGN_OR_RETURN(size_t polynomial_size,
                        ::private_statistics::prio::internal::MinSizePolynomial(
                            parameters_.bins()));
  PRIO_ASSIGN_OR_RETURN(auto poly_params_n,
                        PolyParams::Create(polynomial_size));
  PRIO_ASSIGN_OR_RETURN(auto poly_params_2n,
                        PolyParams::Create(2 * polynomial_size));

  for (auto& packet : batch.packets()) {
    if (!packet.has_encrypted_payload() || !packet.has_r_pit() ||
        !packet.has_uuid()) {
      return absl::InvalidArgumentError(
          "The batch contains an invalid packet.");
    }

    // Decrypt
    PRIO_ASSIGN_OR_RETURN(
        auto serialized_share,
        PrioEncryption::Decrypt(secret_key_, packet.encrypted_payload()));
    PRIO_ASSIGN_OR_RETURN(PrioDataAndProofShare share,
                          ConvertToShare(serialized_share));

    if (share.h_share_packed.size() != polynomial_size) {
      return absl::InvalidArgumentError(
          "The batch contains a packet with an incorrect number of h "
          "coefficients.");
    }

    // Create the validity share
    proto::PrioValiditySharePacket validity_packet;
    proto::PrioValidityShare validity_share;
    if (packet.r_pit().size() != sizeof(FieldElement)) {
      return absl::InvalidArgumentError("r_pit is not properly set.");
    }
    FieldElement r_pit =
        *reinterpret_cast<const FieldElement*>(packet.r_pit().data());
    std::vector<FieldElement> f_fft_coeffs, g_fft_coeffs, h_fft_coeffs;
    f_fft_coeffs.resize(polynomial_size);
    g_fft_coeffs.resize(polynomial_size);
    h_fft_coeffs.resize(polynomial_size * 2);
    f_fft_coeffs[0] = share.f_0_share;
    g_fft_coeffs[0] = share.g_0_share;
    for (size_t i = 0; i < share.data_share.size(); i++) {
      f_fft_coeffs[1 + i] = share.data_share[i];
      g_fft_coeffs[1 + i] = (type_ == MAIN) ? SubMod(share.data_share[i], 1)
                                            : share.data_share[i];
    }
    h_fft_coeffs[0] = share.h_0_share;
    for (size_t i = 0; i < polynomial_size; i++) {
      // Setting the coefficients of h, skipping those that should be equal to
      // 0.
      h_fft_coeffs[1 + 2 * i] = share.h_share_packed[i];
    }

    PRIO_ASSIGN_OR_RETURN(Poly f,
                          Poly::InverseFft(f_fft_coeffs, poly_params_n.get()));
    PRIO_ASSIGN_OR_RETURN(Poly g,
                          Poly::InverseFft(g_fft_coeffs, poly_params_n.get()));
    PRIO_ASSIGN_OR_RETURN(Poly h,
                          Poly::InverseFft(h_fft_coeffs, poly_params_2n.get()));
    PRIO_ASSIGN_OR_RETURN(auto eval_f, f.EvaluateIn(r_pit));
    PRIO_ASSIGN_OR_RETURN(auto eval_g, g.EvaluateIn(r_pit));
    PRIO_ASSIGN_OR_RETURN(auto eval_h, h.EvaluateIn(r_pit));
    validity_share.set_f_r(eval_f);
    validity_share.set_g_r(eval_g);
    validity_share.set_h_r(eval_h);
    *validity_packet.mutable_validity_share() = validity_share;
    validity_packet.set_uuid(packet.uuid());
    *validity_batch.add_packets() = validity_packet;
    // Store
    shares_[packet.uuid()] = std::make_pair(share, validity_share);
  }

  return validity_batch;
}

auto SimplifiedServer::CheckValidityAndAggregate(
    const proto::PrioValidityShareBatch& other_server_validity_share_batch)
    -> absl::StatusOr<std::pair<proto::PrioSumPart, size_t>> {
  size_t number_valid = 0;
  std::vector<FieldElement> aggregate(parameters_.bins());
  proto::PrioSumPart sum_part;

  for (auto& packet : other_server_validity_share_batch.packets()) {
    if (!packet.has_validity_share() || !packet.has_uuid() ||
        shares_.count(packet.uuid()) == 0) {
      return absl::InvalidArgumentError(
          "The batch contains an invalid packet.");
    }

    // Get the validity share
    PrioDataAndProofShare share = std::get<0>(shares_[packet.uuid()]);
    proto::PrioValidityShare v1 = std::get<1>(shares_[packet.uuid()]);
    const proto::PrioValidityShare& v2 = packet.validity_share();
    if (share.data_share.size() != aggregate.size()) {
      return absl::InvalidArgumentError("Invalid size");
    }
    auto f_r = AddMod(static_cast<FieldElement>(v1.f_r()),
                      static_cast<FieldElement>(v2.f_r()));
    auto g_r = AddMod(static_cast<FieldElement>(v1.g_r()),
                      static_cast<FieldElement>(v2.g_r()));
    auto h_r = AddMod(static_cast<FieldElement>(v1.h_r()),
                      static_cast<FieldElement>(v2.h_r()));
    // If valid, aggregate.
    if (MulMod(f_r, g_r) == h_r) {
      number_valid++;
      for (size_t j = 0; j < share.data_share.size(); j++) {
        aggregate[j] = AddMod(aggregate[j], share.data_share[j]);
      }
    }
  }

  std::string serialized = internal::Serialize(aggregate);
  sum_part.set_value_sum(serialized);
  return std::make_pair(sum_part, number_valid);
}

absl::StatusOr<std::vector<FieldElement>> SimplifiedServer::Add(
    const proto::PrioSumPart& sum_part_1,
    const proto::PrioSumPart& sum_part_2) {
  if (!sum_part_1.has_value_sum() || !sum_part_2.has_value_sum()) {
    return absl::InvalidArgumentError("The sum parts are invalid.");
  }
  const std::string& serialized_sum_1 = sum_part_1.value_sum();
  const std::string& serialized_sum_2 = sum_part_2.value_sum();
  if (serialized_sum_1.size() != serialized_sum_2.size()) {
    return absl::InvalidArgumentError(
        "The serializations are not of the same size.");
  }
  PRIO_ASSIGN_OR_RETURN(auto vector_1, internal::Deserialize(serialized_sum_1));
  PRIO_ASSIGN_OR_RETURN(auto vector_2, internal::Deserialize(serialized_sum_2));

  // Compute the sum
  std::vector<FieldElement> out;
  out.reserve(vector_1.size());
  for (size_t i = 0; i < vector_1.size(); i++) {
    out.push_back(AddMod(vector_1[i], vector_2[i]));
  }
  return out;
}

absl::StatusOr<PrioDataAndProofShare> SimplifiedServer::ConvertToShare(
    absl::string_view input) {
  PRIO_ASSIGN_OR_RETURN(
      auto serialization_size,
      ::private_statistics::prio::internal::SerializationLengthBytes(
          parameters_));

  switch (type_) {
    case SimplifiedServer::FACILITATOR:
      // The server is a facilitator and received a seed, it expands it into
      // a share.
      if (input.size() == Aes128CtrSeededPrng::SeedSize()) {
        Aes128CtrSeededPrng prng;
        return ExpandToShare(input, parameters_, &prng);
      }
      break;
    case SimplifiedServer::MAIN:
      // The server is the main server, and received the serialization of a full
      // share.
      if (input.size() == serialization_size) {
        return DeserializeShare(input, parameters_);
      }
      break;
  }

  return absl::InvalidArgumentError(
      "The serialized input is invalid for this server.");
}

}  // namespace testing
}  // namespace prio
}  // namespace private_statistics
