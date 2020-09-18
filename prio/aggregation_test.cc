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

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <glog/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "prio/client.h"
#include "prio/finite_field.h"
#include "prio/prng/aes_128_ctr_seeded_prng.h"
#include "prio/proto/data_share_batch.pb.h"
#include "prio/testing/keys.h"
#include "prio/testing/simplified_server.h"
#include "prio/testing/status_matchers.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {
namespace {
using proto::PrioAlgorithmParameters;

const size_t kDimension = 50;
const size_t kClients = 500;

TEST(AggregationTest, WorksAsExpectedWithOneHotRandomizedResponse) {
  unsigned seed = 123;

  // We want to output to be about +/- 5 off. It's quite approximative, but we
  // select the bias = 1  / (1+exp(epsilon)), hence epsilon, to so that kClients
  // * bias <= 5.
  double epsilon = std::log(kClients / 5.0 - 1);

  // Create the parameters of the aggregation, and a vector that will hold the
  // true sum.
  PrioAlgorithmParameters parameters;
  parameters.set_bins(kDimension);
  parameters.set_epsilon(epsilon);
  parameters.set_hamming_weight(1);
  std::vector<uint32_t> true_sum(kDimension);

  // Create two (simplified) servers.
  testing::SimplifiedServer server1(parameters, testing::SimplifiedServer::MAIN,
                                    testing::PemKeys[1].certificate,
                                    testing::PemKeys[1].secret_key);
  testing::SimplifiedServer server2(
      parameters, testing::SimplifiedServer::FACILITATOR,
      testing::PemKeys[0].certificate, testing::PemKeys[0].secret_key);

  // Vector of public keys.
  std::vector<std::string> certificates = {server1.GetCertificate(),
                                           server2.GetCertificate()};

  // Create a binomial distribution to simulate the clients' inputs.
  std::mt19937 gen(seed);
  auto binomial = std::binomial_distribution<uint32_t>(kDimension - 1);

  // Create the batches for the servers
  proto::PrioDataShareBatch batch_1;
  proto::PrioDataShareBatch batch_2;

  for (size_t i = 0; i < kClients; i++) {
    LOG(INFO) << "Handling client #" << i;
    proto::PrioDataSharePacket packet_1, packet_2;

    // Set uuid
    std::string uuid = std::to_string(i);
    packet_1.set_uuid(uuid);
    packet_2.set_uuid(uuid);

    // Set r_PIT
    PRIO_ASSERT_OK_AND_ASSIGN(FieldElement r_pit, GenerateRandomFieldElement());
    packet_1.set_r_pit(&r_pit, sizeof(r_pit));
    packet_2.set_r_pit(&r_pit, sizeof(r_pit));

    // Create the input for this client.
    std::vector<uint32_t> input(kDimension);
    const int bin = binomial(gen);
    input[bin] = 1;

    // Create client's output.
    PRIO_ASSERT_OK_AND_ASSIGN(auto client,
                              Client::Create(parameters, certificates));
    PRIO_ASSERT_OK_AND_ASSIGN(auto encrypted_shares_server,
                              client.ProcessInput(std::move(input)));

    // Update the packets and batches.
    packet_1.set_encrypted_payload(encrypted_shares_server[0]);
    packet_2.set_encrypted_payload(encrypted_shares_server[1]);
    *batch_1.add_packets() = packet_1;
    *batch_2.add_packets() = packet_2;

    // Update the true sum.
    true_sum[bin]++;
  }

  // Each server processes the batches
  LOG(INFO) << "Processing data batches";
  PRIO_ASSERT_OK_AND_ASSIGN(
      proto::PrioValidityShareBatch validity_share_batch_1,
      server1.ProcessBatch(batch_1));
  PRIO_ASSERT_OK_AND_ASSIGN(
      proto::PrioValidityShareBatch validity_share_batch_2,
      server2.ProcessBatch(batch_2));

  // Each server verifies the validity and aggregate
  LOG(INFO) << "Processing validity batches";
  PRIO_ASSERT_OK_AND_ASSIGN(
      auto server1_validate_output,
      server1.CheckValidityAndAggregate(validity_share_batch_2));
  proto::PrioSumPart sum_part_1 = std::get<0>(server1_validate_output);
  size_t number_valid_1 = std::get<1>(server1_validate_output);
  PRIO_ASSERT_OK_AND_ASSIGN(
      auto server2_validate_output,
      server2.CheckValidityAndAggregate(validity_share_batch_1));
  proto::PrioSumPart sum_part_2 = std::get<0>(server2_validate_output);
  size_t number_valid_2 = std::get<1>(server2_validate_output);

  // Check that they are all valid
  EXPECT_EQ(number_valid_1, kClients);
  EXPECT_EQ(number_valid_2, kClients);

  // The recipient computes the sum.
  LOG(INFO) << "Computing final sum";
  PRIO_ASSERT_OK_AND_ASSIGN(
      std::vector<FieldElement> sum,
      testing::SimplifiedServer::Add(sum_part_1, sum_part_2));

  std::stringstream out;
  for (size_t i = 0; i < kDimension; i++) out << i << ",";
  out << "0\n";
  for (const auto& i : true_sum) out << i << ",";
  out << "0\n";
  for (const auto& i : sum) out << i << ",";
  out << "0\n";
  LOG(INFO) << out.str();
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
