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

#ifndef LIBPRIO_CC_PRIO_TESTING_SIMPLIFIED_SERVER_H_
#define LIBPRIO_CC_PRIO_TESTING_SIMPLIFIED_SERVER_H_

#include <utility>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "prio/client.h"
#include "prio/data.h"
#include "prio/encryption.h"
#include "prio/finite_field.h"
#include "prio/poly.h"
#include "prio/prng/aes_128_ctr_seeded_prng.h"
#include "prio/proto/algorithm_parameters.pb.h"
#include "prio/proto/data_share_batch.pb.h"
#include "prio/proto/sum_part.pb.h"
#include "prio/proto/validity_batch.pb.h"
#include "prio/serialization.h"
#include "prio/status_macros.h"
#include "prio/types.h"
#include "prio/util.h"

namespace private_statistics {
namespace prio {
namespace testing {

// Implementation of a simplified server, which aggregates the data shares.
class SimplifiedServer {
 public:
  // There are two types of servers:
  // - facilitator servers, which receive an encrypted seed that is being
  //   expanded into a random share,
  // - one main server, which receives an encrypted share.
  // The servers produce SNIPs (secret-shared non-interactive proofs) from a
  // batch of encrypted seeds/shares, and aggregate shares when its SNIPs and
  // those of the facilitator servers are valid.
  enum Type { FACILITATOR, MAIN };

  SimplifiedServer(proto::PrioAlgorithmParameters parameters, Type type,
                   absl::string_view cert_pem, absl::string_view key_pem)
      : parameters_(parameters),
        certificate_(cert_pem),
        secret_key_(PrioSecretKey::ParsePemKey(key_pem).value()),
        type_(type) {}

  // Process the batch of shares.
  auto ProcessBatch(const proto::PrioDataShareBatch& batch)
      -> absl::StatusOr<proto::PrioValidityShareBatch>;

  // Process the validity batches and aggregate.
  auto CheckValidityAndAggregate(
      const proto::PrioValidityShareBatch& other_server_validity_share_batch)
      -> absl::StatusOr<std::pair<proto::PrioSumPart, size_t>>;

  // Process the sum parts.
  static absl::StatusOr<std::vector<FieldElement>> Add(
      const proto::PrioSumPart& sum_part_1,
      const proto::PrioSumPart& sum_part_2);

  // Get the certificate.
  const std::string GetCertificate() const { return certificate_; }

 private:
  // Convert a string to a share, depending on the type of the server.
  absl::StatusOr<PrioDataAndProofShare> ConvertToShare(absl::string_view input);

  // We store the content of the share, and the server's own validity proof,
  // under the key uuid.
  std::map<std::string,
           std::pair<PrioDataAndProofShare, proto::PrioValidityShare>>
      shares_;
  proto::PrioAlgorithmParameters parameters_;
  std::string certificate_;
  PrioSecretKey secret_key_;
  Type type_;
};

}  // namespace testing
}  // namespace prio
}  // namespace private_statistics

#endif  // LIBPRIO_CC_PRIO_TESTING_SIMPLIFIED_SERVER_H_
