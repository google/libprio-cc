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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "prio/encryption.h"
#include "prio/prng/aes_128_ctr_seeded_prng.h"
#include "prio/proto/algorithm_parameters.pb.h"
#include "prio/serialization.h"
#include "prio/testing/keys.h"
#include "prio/testing/status_matchers.h"

namespace private_statistics {
namespace prio {
namespace {

using proto::PrioAlgorithmParameters;
using ::testing::HasSubstr;
using testing::StatusIs;

class ClientTest : public ::testing::Test {
 protected:
  void SetUp() override {
    certificates_.reserve(testing::PemKeys.size());
    secret_keys_.reserve(testing::PemKeys.size());
    for (const auto& key_material : testing::PemKeys) {
      certificates_.emplace_back(key_material.certificate);
      public_keys_.push_back(
          PrioPublicKey::ParsePemCertificate(key_material.certificate).value());
      secret_keys_.push_back(
          PrioSecretKey::ParsePemKey(key_material.secret_key).value());
    }
  }

  std::vector<PrioPublicKey> GetPublicKeys() {
    std::vector<PrioPublicKey> public_keys;
    public_keys.reserve(certificates_.size());
    for (const auto& cert : certificates_) {
      public_keys.push_back(PrioPublicKey::ParsePemCertificate(cert).value());
    }
    return public_keys;
  }

  std::vector<std::string> certificates_;
  std::vector<PrioPublicKey> public_keys_;
  std::vector<PrioSecretKey> secret_keys_;
};

TEST_F(ClientTest, InvalidPrime) {
  PrioAlgorithmParameters parameters;

  parameters.set_prime(
      static_cast<uint64_t>(2147483647));  // 8th Mersenne prime.

  EXPECT_THAT(Client::Create(parameters, GetPublicKeys()),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("prime is not supported")));
  EXPECT_THAT(Client::Create(parameters, certificates_),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("prime is not supported")));
}

TEST_F(ClientTest, InvalidNumberServers) {
  PrioAlgorithmParameters parameters;

  parameters.set_number_servers(3);

  EXPECT_THAT(Client::Create(parameters, GetPublicKeys()),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("number_servers is not supported")));
  EXPECT_THAT(Client::Create(parameters, certificates_),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("number_servers is not supported")));
}

TEST_F(ClientTest, InvalidEpsilon) {
  PrioAlgorithmParameters parameters;
  parameters.set_epsilon(-1.0);

  EXPECT_THAT(Client::Create(parameters, GetPublicKeys()),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("epsilon cannot be negative")));
  EXPECT_THAT(Client::Create(parameters, certificates_),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("epsilon cannot be negative")));
}

TEST_F(ClientTest, UnspecifiedBins) {
  PrioAlgorithmParameters parameters;

  EXPECT_THAT(Client::Create(parameters, GetPublicKeys()),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("number of bins is not specified")));
  EXPECT_THAT(Client::Create(parameters, certificates_),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("number of bins is not specified")));
}

TEST_F(ClientTest, InvalidBins) {
  PrioAlgorithmParameters parameters;

  parameters.set_bins(0);

  EXPECT_THAT(Client::Create(parameters, GetPublicKeys()),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("number of bins cannot be non-positive")));
  EXPECT_THAT(Client::Create(parameters, certificates_),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("number of bins cannot be non-positive")));
}

TEST_F(ClientTest, EmptyInput) {
  PrioAlgorithmParameters parameters;
  parameters.set_bins(1);
  PRIO_ASSERT_OK_AND_ASSIGN(auto client,
                            Client::Create(parameters, GetPublicKeys()));

  std::vector<uint32_t> input = {};

  EXPECT_THAT(client.ProcessInput(input),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("should not be empty")));
}

TEST_F(ClientTest, InputSizeDiffers) {
  PrioAlgorithmParameters parameters;
  parameters.set_bins(2);
  PRIO_ASSERT_OK_AND_ASSIGN(auto client,
                            Client::Create(parameters, GetPublicKeys()));

  std::vector<uint32_t> input = {0};  // size 1

  EXPECT_THAT(client.ProcessInput(input),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("input size differ")));
}

TEST_F(ClientTest, NotBitVector) {
  PrioAlgorithmParameters parameters;
  parameters.set_bins(2);
  PRIO_ASSERT_OK_AND_ASSIGN(auto client,
                            Client::Create(parameters, GetPublicKeys()));

  std::vector<uint32_t> input = {0, 2};

  EXPECT_THAT(client.ProcessInput(input),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("should be a bitvector")));
}

TEST_F(ClientTest, HammingWeightIncorrectInParameters) {
  PrioAlgorithmParameters parameters;
  parameters.set_bins(2);

  parameters.set_hamming_weight(0);
  EXPECT_THAT(Client::Create(parameters, GetPublicKeys()),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("hamming weight has to be in the range")));

  parameters.set_hamming_weight(parameters.bins());
  EXPECT_THAT(Client::Create(parameters, GetPublicKeys()),
              StatusIs(absl::StatusCode::kUnimplemented,
                       HasSubstr("hamming weight has to be in the range")));
}

TEST_F(ClientTest, HammingWeightIncorrectInInput) {
  PrioAlgorithmParameters parameters;
  parameters.set_bins(5);
  parameters.set_hamming_weight(2);
  PRIO_ASSERT_OK_AND_ASSIGN(auto client,
                            Client::Create(parameters, GetPublicKeys()));

  std::vector<uint32_t> input = {0, 0, 1, 0, 0};  // Hamming weight = 1

  EXPECT_THAT(client.ProcessInput(input),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Hamming weight of the input is incorrect")));
}

TEST_F(ClientTest, WorksWithoutHammingWeight) {
  PrioAlgorithmParameters parameters;
  parameters.set_bins(2);
  std::vector<uint32_t> input = {0, 1};

  PRIO_ASSERT_OK_AND_ASSIGN(auto client,
                            Client::Create(parameters, GetPublicKeys()));
  PRIO_ASSERT_OK_AND_ASSIGN(auto client_from_certificates,
                            Client::Create(parameters, certificates_));
  PRIO_ASSERT_OK_AND_ASSIGN(auto encrypted_shares, client.ProcessInput(input));
  PRIO_ASSERT_OK_AND_ASSIGN(auto encrypted_shares2,
                            client_from_certificates.ProcessInput(input));

  // Decrypt the shares with the corresponding secret keys.
  std::vector<std::string> shares, shares2;
  shares.resize(parameters.number_servers());
  shares2.resize(parameters.number_servers());
  for (int i = 0; i < parameters.number_servers(); i++) {
    PRIO_ASSERT_OK_AND_ASSIGN(
        shares[i],
        PrioEncryption::Decrypt(secret_keys_[i], encrypted_shares[i]));
    PRIO_ASSERT_OK_AND_ASSIGN(
        shares2[i],
        PrioEncryption::Decrypt(secret_keys_[i], encrypted_shares2[i]));
  }

  PRIO_ASSERT_OK(DeserializeShare(shares[0], parameters));
  PRIO_ASSERT_OK(DeserializeShare(shares2[0], parameters));
  EXPECT_EQ(shares[1].size(), Aes128CtrSeededPrng::SeedSize());
  EXPECT_EQ(shares2[1].size(), Aes128CtrSeededPrng::SeedSize());
}

TEST_F(ClientTest, WorksWithHammingWeight) {
  PrioAlgorithmParameters parameters;
  parameters.set_bins(5);
  parameters.set_hamming_weight(2);
  std::vector<uint32_t> input = {0, 1, 0, 0, 1};

  PRIO_ASSERT_OK_AND_ASSIGN(auto client,
                            Client::Create(parameters, GetPublicKeys()));
  PRIO_ASSERT_OK_AND_ASSIGN(auto client_from_certificates,
                            Client::Create(parameters, certificates_));
  PRIO_ASSERT_OK_AND_ASSIGN(auto encrypted_shares, client.ProcessInput(input));
  PRIO_ASSERT_OK_AND_ASSIGN(auto encrypted_shares2,
                            client_from_certificates.ProcessInput(input));

  // Decrypt the shares with the corresponding secret keys.
  std::vector<std::string> shares, shares2;
  shares.resize(parameters.number_servers());
  shares2.resize(parameters.number_servers());
  for (int i = 0; i < parameters.number_servers(); i++) {
    PRIO_ASSERT_OK_AND_ASSIGN(
        shares[i],
        PrioEncryption::Decrypt(secret_keys_[i], encrypted_shares[i]));
    PRIO_ASSERT_OK_AND_ASSIGN(
        shares2[i],
        PrioEncryption::Decrypt(secret_keys_[i], encrypted_shares2[i]));
  }

  PRIO_ASSERT_OK(DeserializeShare(shares[0], parameters));
  PRIO_ASSERT_OK(DeserializeShare(shares2[0], parameters));
  EXPECT_EQ(shares[1].size(), Aes128CtrSeededPrng::SeedSize());
  EXPECT_EQ(shares2[1].size(), Aes128CtrSeededPrng::SeedSize());
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
