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

#include "prio/encryption.h"

#include <fstream>
#include <memory>

#include <glog/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include <openssl/base.h>
#include <openssl/ec.h>
#include "prio/testing/keys.h"
#include "prio/testing/status_matchers.h"

namespace private_statistics {
namespace prio {

// We start by testing the internal functions.
namespace internal {
namespace {

TEST(EndianessTest, ConversionBigEndianBytes) {
  std::vector<uint8_t> big_endian_vector = Uint32ToBigEndianBytes(0x12345678);
  std::vector<uint8_t> expected = {0x12, 0x34, 0x56, 0x78};
  EXPECT_EQ(big_endian_vector, expected);

  big_endian_vector = Uint32ToBigEndianBytes(1);
  expected = {0x00, 0x00, 0x00, 0x01};
  EXPECT_EQ(big_endian_vector, expected);
}

TEST(KdfTest, Interoperability) {
  //                k    d    f   _   i     n    p    u    t
  std::string z = {107, 100, 102, 95, 105, 110, 112, 117, 116};
  //                          e    p    h   e     m    e    r   a     l
  //                         _     k    e    y   _     d    a    t    a
  std::string shared_info = {101, 112, 104, 101, 109, 101, 114, 97,  108,
                             95,  107, 101, 121, 95,  100, 97,  116, 97};

  // Check the expected KDF output, obtained as follows (in Python):
  // from cryptography.hazmat.backends import default_backend
  // from cryptography.hazmat.primitives.kdf import x963kdf
  // from cryptography.hazmat.primitives import hashes
  // x963kdf.X963KDF(
  //   algorithm=hashes.SHA256(),
  //   length=32,
  //   sharedinfo=b'ephemeral_key_data',
  //   backend=default_backend()).derive(b'kdf_input')
  std::vector<uint8_t> expected = {242, 39,  132, 56,  177, 122, 246, 253,
                                   22,  20,  105, 121, 61,  90,  205, 204,
                                   142, 200, 0,   167, 150, 109, 235, 75,
                                   235, 251, 176, 10,  40,  119, 186, 93};

  EXPECT_EQ(X963KdfOutputs32Bytes(z, shared_info),
            std::string(expected.begin(), expected.end()));
}
}  // namespace
}  // namespace internal

namespace {

TEST(PrioEncryptionTest, EncryptAndDecryptPem) {
  constexpr absl::string_view message = "here is the message to encrypt";

  for (const auto& key_material : testing::PemKeys) {
    PRIO_ASSERT_OK_AND_ASSIGN(
        auto sk, PrioSecretKey::ParsePemKey(key_material.secret_key));
    PRIO_ASSERT_OK_AND_ASSIGN(
        auto pk, PrioPublicKey::ParsePemCertificate(key_material.certificate));

    PRIO_ASSERT_OK_AND_ASSIGN(auto encrypted_message,
                              PrioEncryption::Encrypt(pk, message));

    PRIO_ASSERT_OK_AND_ASSIGN(auto decrypted_message,
                              PrioEncryption::Decrypt(sk, encrypted_message));

    EXPECT_EQ(message, decrypted_message);
  }
}

TEST(PrioEncryptionTest, EncryptAndDecrypt) {
  constexpr absl::string_view message = "here is the message to encrypt";
  constexpr absl::string_view private_key_b64 =
      "BNNOqoU54GPo+1gTPv+hCgA9U2ZCKd76yOMrWa1xTWgeb4LhFLMQIQoRwDVaW64g/"
      "WTdcxT4rDULoycUNFB60LER6hPEHg/ObBnRPV1rwS3nj9Bj0tbjVPPyL9p8QW8B+w==";

  PRIO_ASSERT_OK_AND_ASSIGN(auto sk,
                            PrioSecretKey::ParseFullKeyBase64(private_key_b64));
  PRIO_ASSERT_OK_AND_ASSIGN(auto pk,
                            PrioPublicKey::ParseFullKeyBase64(private_key_b64));
  PRIO_ASSERT_OK_AND_ASSIGN(auto encrypted_message,
                            PrioEncryption::Encrypt(pk, message));
  PRIO_ASSERT_OK_AND_ASSIGN(auto decrypted_message,
                            PrioEncryption::Decrypt(sk, encrypted_message));

  EXPECT_EQ(message, decrypted_message);
}

// We ensure interoperability with the rust implementation of libprio:
// - https://github.com/abetterinternet/libprio-rs/blob/master/src/encrypt.rs
TEST(PrioEncryptionTest, InteroperabilityLibPrioRs) {
  // Constants for server 1.
  constexpr absl::string_view private_key1_b64 =
      "BIl6j+J6dYttxALdjISDv6ZI4/"
      "VWVEhUzaS05LgrsfswmbLOgNt9HUC2E0w+"
      "9RqZx3XMkdEHBHfNuCSMpOwofVSq3TfyKwn0NrftKisKKVSaTOt5seJ67P5QL4hxgPWvxw="
      "=";
  constexpr absl::string_view share1_b64 =
      "Kbnd2ZWrsfLfcpuxHffMrJ1b7sCrAsNqlb6Y1eAMfwCVUNXt";
  constexpr absl::string_view encrypted_share1_b64 =
      "BEWObg41JiMJglSEA6Ebk37xOeflD2a1t2eiLmX0OPccJhAER5NmOI+"
      "4r4Cfm7aJn141sGKnTbCuIB9+AeVuwMAQnzjsGPu5aNgkdpp+"
      "6VowAcVAV1DlzZvtwlQkCFlX4f3xmafTPFTPOokYi2a+H1n8GKwd";
  // Constants for server 2.
  constexpr absl::string_view private_key2_b64 =
      "BNNOqoU54GPo+1gTPv+hCgA9U2ZCKd76yOMrWa1xTWgeb4LhFLMQIQoRwDVaW64g/"
      "WTdcxT4rDULoycUNFB60LER6hPEHg/ObBnRPV1rwS3nj9Bj0tbjVPPyL9p8QW8B+w==";
  constexpr absl::string_view share2_b64 = "hu+vT3+8/taHP7B/dWXh/g==";
  constexpr absl::string_view encrypted_share2_b64 =
      "BNRzQ6TbqSc4pk0S8aziVRNjWm4DXQR5yCYTK2w22iSw4XAPW4OB9RxBpWVa1C/3ywVBT/"
      "3yLArOMXEsCEMOG1+d2CiEvtuU1zADH2MVaCnXL/dVXkDchYZsvPWPkDcjQA==";

  // Decode the ciphertexts.
  std::string encrypted_share1, encrypted_share2;
  EXPECT_TRUE(absl::Base64Unescape(encrypted_share1_b64, &encrypted_share1));
  EXPECT_TRUE(absl::Base64Unescape(encrypted_share2_b64, &encrypted_share2));

  // Parse the secret keys.
  PRIO_ASSERT_OK_AND_ASSIGN(
      auto sk1, PrioSecretKey::ParseFullKeyBase64(private_key1_b64));
  PRIO_ASSERT_OK_AND_ASSIGN(
      auto sk2, PrioSecretKey::ParseFullKeyBase64(private_key2_b64));

  // Decrypt the shares.
  PRIO_ASSERT_OK_AND_ASSIGN(std::string share1_decrypted,
                            PrioEncryption::Decrypt(sk1, encrypted_share1));
  PRIO_ASSERT_OK_AND_ASSIGN(std::string share2_decrypted,
                            PrioEncryption::Decrypt(sk2, encrypted_share2));

  // Verify that the decryptions are correct.
  std::string share1_decoded, share2_decoded;
  ASSERT_TRUE(absl::Base64Unescape(share1_b64, &share1_decoded));
  ASSERT_TRUE(absl::Base64Unescape(share2_b64, &share2_decoded));
  EXPECT_EQ(share1_decrypted, share1_decoded);
  EXPECT_EQ(share2_decrypted, share2_decoded);
}

// We ensure interoperability with Apple's implementation by using test vectors
// https://github.com/zssz/AppleCryptoInteroperability/blob/master/applecryptointeroperability/src/androidTest/java/company/ize/applecryptointeroperability/InstrumentedTest.kt
TEST(PrioEncryptionTest, InteroperabilityAppleCrypto) {
  constexpr absl::string_view private_key_b64 =
      "BBMRAqnDqG1Deru7d51hiOaE0T9sj4nivVH3PAfGJtDbN5uP30m7aZFpcI/"
      "qIJju5lE9iz55xIIengu0NqGTdQs/"
      "cjiVMrMto+8M2H5VQyjKlHrnBl121xmDIlEKtXnCLA==";
  constexpr absl::string_view plaintext = "Hello, World!";
  constexpr absl::string_view encrypted_message_b64 =
      "BLABoEXShyyRJYaXPmwseK2pVA5AoFgdilIlMb2QA3fquvQ3HWXq8LLG6d/"
      "d+7kDeF+ipKsyD8bqieC8JQTCrg2sQBxifQZpM3KG5kdh42VzA1o2DHQoo5nEJ5q0hQ==";

  std::string encrypted_message;
  EXPECT_TRUE(absl::Base64Unescape(encrypted_message_b64, &encrypted_message));

  PRIO_ASSERT_OK_AND_ASSIGN(auto sk,
                            PrioSecretKey::ParseFullKeyBase64(private_key_b64));
  PRIO_ASSERT_OK_AND_ASSIGN(std::string decrypted,
                            PrioEncryption::Decrypt(sk, encrypted_message));

  EXPECT_EQ(decrypted, plaintext);
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
