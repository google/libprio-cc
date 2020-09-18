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

#ifndef PRIVATE_ANALYTICS_PRIO_CLIENT_H_
#define PRIVATE_ANALYTICS_PRIO_CLIENT_H_

#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "prio/encryption.h"
#include "prio/proto/algorithm_parameters.pb.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {

// This class implements a client in  Prio. Prio is a privacy-preserving system
// for the collection of aggregate statistics, described in
// https://crypto.stanford.edu/prio/paper.pdf.
class Client {
 public:
  // Factory function to instantiate a client. It takes as input Prio
  // parameters, and the public keys (or ceertificates) of the destination
  // servers.
  //
  // This function returns an kUnimplemented status code when:
  // - the parameters contain an unsupported prime;
  // - the parameters contain an unsupported number of servers;
  // - the parameters do not contain the number of bins;
  // - the value of epsilon is less or equal to 0.
  // - hamming_weight is specified to be <=0 or >= number of bins.
  // This function returns an kInvalidArgument status code if there are not
  // enough public keys or if they are invalid.
  static absl::StatusOr<Client> Create(
      const proto::PrioAlgorithmParameters& parameters,
      std::vector<PrioPublicKey> public_keys);
  static absl::StatusOr<Client> Create(
      const proto::PrioAlgorithmParameters& parameters,
      const std::vector<std::string>& certificates);

  // Create encrypted data packets from an input.
  //
  // The `input` will be secret shared, and associated secret-shared
  // non-interactive proofs (SNIPs) will be created for the servers. The output
  // are the encryptions of the serialized packets to be sent to each server.
  //
  // This function returns a kInvalidArgumentError if:
  // - the input is empty;
  // - the parameters contain a number of bins that differ from the size of the
  //   input;
  // - the parameters contain an Hamming weight which differs from the input's
  //   Hamming weight;
  absl::StatusOr<std::vector<std::string>> ProcessInput(
      const std::vector<uint32_t>& input);

 private:
  // Private constructor.
  explicit Client(const proto::PrioAlgorithmParameters& parameters,
                  std::vector<PrioPublicKey> public_keys)
      : parameters_(parameters), public_keys_(std::move(public_keys)) {}
  proto::PrioAlgorithmParameters parameters_;
  std::vector<PrioPublicKey> public_keys_;
};

}  // namespace prio
}  // namespace private_statistics

#endif  // PRIVATE_ANALYTICS_PRIO_CLIENT_H_
