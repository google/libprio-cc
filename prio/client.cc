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

#include "prio/client.h"

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include <openssl/ec.h>
#include "prio/constants.h"
#include "prio/encryption.h"
#include "prio/finite_field.h"
#include "prio/poly.h"
#include "prio/prng/aes_128_ctr_seeded_prng.h"
#include "prio/randomized_response.h"
#include "prio/serialization.h"
#include "prio/status_macros.h"
#include "prio/types.h"
#include "prio/util.h"

namespace private_statistics {
namespace prio {

namespace {
using proto::PrioAlgorithmParameters;
}

absl::StatusOr<Client> Client::Create(const PrioAlgorithmParameters& parameters,
                                      std::vector<PrioPublicKey> public_keys) {
  // Check if the prime is valid.
  if (parameters.prime() != kPrioModulus) {
    return absl::UnimplementedError(
        "Client::Create: The prime is not supported.");
  }
  // Check if the number of servers is valid.
  if (parameters.number_servers() != kDefaultNumberOfServers) {
    return absl::UnimplementedError(
        "Client::Create: The number_servers is not supported.");
  }
  // Check if the value of epsilon is valid.
  if (parameters.epsilon() < 0) {
    return absl::UnimplementedError(
        "Client::Create: The epsilon cannot be negative.");
  }
  // Check if the value of bins is specified and valid.
  if (!parameters.has_bins()) {
    return absl::UnimplementedError(
        "Client::Create: The number of bins is not specified.");
  } else if (parameters.bins() <= 0) {
    return absl::UnimplementedError(
        "Client::Create: The number of bins cannot be non-positive.");
  }
  // Check if hamming weight is specified, and if so, if it is valid.
  if (parameters.has_hamming_weight()) {
    if (parameters.hamming_weight() <= 0 ||
        parameters.hamming_weight() >= parameters.bins()) {
      return absl::UnimplementedError(
          "Client::Create: The hamming weight has to be in the range (0, "
          "bins).");
    }
  }

  // Check that the right number of public_keys is provided.
  if (static_cast<size_t>(parameters.number_servers()) != public_keys.size()) {
    return absl::InvalidArgumentError(
        "Client::Create: The number of public_keys does not match the number "
        "of servers.");
  }

  // Parameters and public_keys are correct. Let's construct the client.
  return Client(parameters, std::move(public_keys));
}

absl::StatusOr<Client> Client::Create(
    const PrioAlgorithmParameters& parameters,
    const std::vector<std::string>& certificates) {
  std::vector<PrioPublicKey> public_keys;
  public_keys.reserve(certificates.size());
  for (const auto& certificate : certificates) {
    PRIO_ASSIGN_OR_RETURN(auto public_key,
                          PrioPublicKey::ParsePemCertificate(certificate));
    public_keys.push_back(std::move(public_key));
  }
  return Create(parameters, std::move(public_keys));
}

absl::StatusOr<std::vector<std::string>> Client::ProcessInput(
    const std::vector<uint32_t>& input) {
  // Check that the input is not empty.
  if (input.empty()) {
    return absl::InvalidArgumentError(
        "Client::ProcessInput: The input to the aggregation should not be "
        "empty.");
  }

  // Check that the input as the same size as in the parameters.
  if (parameters_.has_bins()) {
    if (input.size() != static_cast<size_t>(parameters_.bins())) {
      return absl::InvalidArgumentError(
          "Client::ProcessInput: The input size differs than the one expected "
          "in the parameters.");
    }
  }

  // The current implementation of Prio assumes that the inputs are bits, so we
  // check that the input is a bitvector. We also compute the Hamming weight of
  // the input.
  int hamming_weight_input = 0;
  for (const FieldElement& element : input) {
    if (element > 1) {
      return absl::InvalidArgumentError(
          "Client::ProcessInput: The input should be a bitvector.");
    }
    hamming_weight_input += element;
  }

  // Check the Hamming weight of the input
  if (parameters_.has_hamming_weight() &&
      parameters_.hamming_weight() != hamming_weight_input) {
    return absl::InvalidArgumentError(
        "Client::ProcessInput: The Hamming weight of the input is incorrect.");
  }

  // We apply local differential privacy via randomized response *before
  // aggregation*.
  PRIO_ASSIGN_OR_RETURN(auto randomizer, Randomizer::Create(parameters_));
  PRIO_ASSIGN_OR_RETURN(std::vector<uint32_t> randomized_input,
                        randomizer.RandomizeResponse(input));

  // Compute the smallest power of two for the dimension.
  PRIO_ASSIGN_OR_RETURN(size_t dimension,
                        internal::MinSizePolynomial(input.size()));

  // Construct two polynomials f and g, whose FFT coefficients are
  // - f_0 and g_0 are random
  // - f_i = input(i) and g_i = input(i) - 1.
  PRIO_ASSIGN_OR_RETURN(auto params_n, PolyParams::Create(dimension));
  std::vector<FieldElement> evaluations_f(dimension);
  std::vector<FieldElement> evaluations_g(dimension);
  PRIO_ASSIGN_OR_RETURN(evaluations_f[0], GenerateRandomFieldElement());
  PRIO_ASSIGN_OR_RETURN(evaluations_g[0], GenerateRandomFieldElement());
  for (size_t i = 0; i < input.size(); i++) {
    evaluations_f[1 + i] = randomized_input[i];
    evaluations_g[1 + i] = SubMod(randomized_input[i], 1);
  }
  PRIO_ASSIGN_OR_RETURN(Poly f,
                        Poly::InverseFft(evaluations_f, params_n.get()));
  PRIO_ASSIGN_OR_RETURN(Poly g,
                        Poly::InverseFft(evaluations_g, params_n.get()));

  // Get the 2*N FFT representations of f and g (which will enable to compute
  // the polynomial h = f*g, of degree <= 2*(N-1)).
  PRIO_ASSIGN_OR_RETURN(auto params_2n, PolyParams::Create(2 * dimension));
  PRIO_ASSIGN_OR_RETURN(auto f_fft_coefficients, f.Fft(params_2n.get()));
  PRIO_ASSIGN_OR_RETURN(auto g_fft_coefficients, g.Fft(params_2n.get()));

  // Create a random secret share from the seed.
  Aes128CtrSeededPrng prng;
  PRIO_ASSIGN_OR_RETURN(std::string seed, prng.GenerateSeed());
  PRIO_ASSIGN_OR_RETURN(PrioDataAndProofShare share_server_2,
                        ExpandToShare(seed, parameters_, &prng));

  // Create share of the first server.
  PrioDataAndProofShare share_server_1;
  share_server_1.data_share = randomized_input;
  share_server_1.f_0_share = f_fft_coefficients[0];
  share_server_1.g_0_share = g_fft_coefficients[0];
  share_server_1.h_0_share =
      MulMod(share_server_1.f_0_share, share_server_1.g_0_share);
  share_server_1.h_share_packed.reserve(dimension);
  for (size_t i = 0; i < 2 * dimension; i += 2) {
    // When i > 0, by definition it holds that every other coefficient
    //   MulMod(f_fft_coefficients[i], g_fft_coefficients[i]) = 0
    // hence we only need to compute the following coefficient of h.
    share_server_1.h_share_packed.push_back(
        MulMod(f_fft_coefficients[1 + i], g_fft_coefficients[1 + i]));
  }
  PRIO_RETURN_IF_ERROR(share_server_1.SubInPlace(share_server_2));

  // Create the output.
  std::vector<std::string> output;
  output.reserve(parameters_.number_servers());
  PRIO_ASSIGN_OR_RETURN(auto serialized_share,
                        SerializeShare(share_server_1, parameters_));
  PRIO_ASSIGN_OR_RETURN(
      auto encrypted_share,
      PrioEncryption::Encrypt(public_keys_[0], serialized_share));
  output.push_back(encrypted_share);
  PRIO_ASSIGN_OR_RETURN(auto encrypted_seed,
                        PrioEncryption::Encrypt(public_keys_[1], seed));
  output.push_back(encrypted_seed);
  return output;
}

}  // namespace prio
}  // namespace private_statistics
