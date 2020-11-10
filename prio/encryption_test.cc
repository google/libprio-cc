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
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include <openssl/base.h>
#include <openssl/ec.h>
#include "prio/testing/keys.h"
#include "prio/testing/status_matchers.h"

namespace private_statistics {
namespace prio {

using ::testing::HasSubstr;
using testing::StatusIs;

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

// Submitting a RSA certificate should fail.
TEST(PrioEncryptionTest, RsaCertificate) {
  constexpr absl::string_view valid_cert =
      "-----BEGIN CERTIFICATE-----\n"
      "MIIFkzCCA3ugAwIBAgIUa0xOaAAjZzfEi48yudEfFKCTEuowDQYJKoZIhvcNAQEL\n"
      "BQAwWTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMRMwEQYDVQQKDApHb29nbGUg\n"
      "TExDMSgwJgYJKoZIhvcNAQkBFhlsaWJwcmlvLWNjLWRldkBnb29nbGUuY29tMB4X\n"
      "DTIwMTAyMjIwMzc1NVoXDTIxMTAyMjIwMzc1NVowWTELMAkGA1UEBhMCVVMxCzAJ\n"
      "BgNVBAgMAk5ZMRMwEQYDVQQKDApHb29nbGUgTExDMSgwJgYJKoZIhvcNAQkBFhls\n"
      "aWJwcmlvLWNjLWRldkBnb29nbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A\n"
      "MIICCgKCAgEAvwGd6gTzWAwmyJ13jkLEH/PyIszCAsslbynMS5zZarYu7vrmJy61\n"
      "1ypnCuCwCAglbV/sza6kdINJd5lXz88LjmXuEDjmNqhQCFDKZvHeyYyou40RkmLS\n"
      "/yYZpHeo1S5LagqAYge3UADc7bZM4EWIvHjrTulAYfqLNi9x913CP13dROpx3FLk\n"
      "zeg+WtVgCl2O6euvDBrTGgOTEf/7Qk/AB4I/99X4/a07Qq07JWU/M4HMD0VEWOOI\n"
      "/lQaGy6omHI0rTNUwkKoL0QBJA5oDfo9m7i2DoIWhtCNUKGkdkiaG4yO5M/F2isF\n"
      "716kRJWYrMa4jCtrtjEZrbmNOPYoyyKnR8gOF5rmStalGXTeAfl5Biif0yLxmhAk\n"
      "FdCmObMnpHyeAkDlNMMvB3TS5KkuDRKT8IE0Gi+ZFqmgiyuuQRAvI7zPUuNpeuST\n"
      "pi/AeYskSemW4BldHmBAI8Kstk1P2m9bFWEEAStv5TKXvnaGW9QTuc6vgR/h7U9+\n"
      "sllQJeZE9SKEuifsvmR7dnhvzBeDvDLsrDImZALGzEfQbTQ8hNBKVMoXRwDeqQAK\n"
      "p1r4uakB4Jko8+oQ5UCago+08XEK4WEIz745uldqxPB/dDPK96qjSHIbb/x0jt2r\n"
      "2Gtk4HQgjt8YJ44MjHOxyDToF7Qs2rFB8orC2Udj/E7w44tqTZAQ/WsCAwEAAaNT\n"
      "MFEwHQYDVR0OBBYEFBdNjmuh5Ze7lXuLpYDig0yfmcdnMB8GA1UdIwQYMBaAFBdN\n"
      "jmuh5Ze7lXuLpYDig0yfmcdnMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n"
      "BQADggIBAFlgq2kxFC1m58b1Fif1VWTGeCYyGy0OxtRLa++xFTXhkTkRj8H7/dFU\n"
      "g2CrXowPVmKRYixjchU9QPXa0IEYp9FVTaYz7C3B62neb1nzBXNJriWtSmwJC1JX\n"
      "nwcM/xyg/ImgS2z40JRIsi3cU6bL3PFMcZLcY3qZMQmc20cjCnEy+1TOKmh/T4TL\n"
      "960HrniPX8lbmr8Gm1275+7SIr02hQ4gzs+5YJrtlQ5P3f49tVhVeXIDW3+kjfJm\n"
      "I/28CGG3SaSArEHG0FLuU8/GjQx0GSQirM3ONB94einYuU07mop0eBImJwpEhxmv\n"
      "rJ+DxcHm4FWs9I5lB5Fr+wjiyKMa+2xUbtjeZUh/CFD3lL/MWr6HuR/eIBEk5Cl1\n"
      "yHtZD9GYi4LJt0jmSnt2tTM6HbS2DFL12Q9fJ5kDmWZiEoiIsZXic20UZzUj8SDN\n"
      "XmWG5nETKMeksYP9zOfnZ3sDmP0AzDAIIxUKl1sGjaE6NcKTWGpOyGrA4VWwc4m2\n"
      "7Q0o7uJw4R30lv/Q1lw1MMMBrQxD8t1+eQ/99+EPSurkkF2KqWK1Ke1DLLWzWd2M\n"
      "WYru9SjfQk7W0k4knTUS9E+cT3Q9sgVxT1pZpUYAukscxIf2UT0ry7liQM8ErLt+\n"
      "pMNznH/5Z+UBd6DtaU+NQDYjumKct1p3FGyXbTQwEAxmGEEQaJ9U\n"
      "-----END CERTIFICATE-----";
  EXPECT_THAT(PrioPublicKey::ParsePemCertificate(valid_cert),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ec_key is null")));
}

// Submitting a RSA private key should fail.
TEST(PrioEncryptionTest, RsaPrivateKey) {
  constexpr absl::string_view private_key =
      "-----BEGIN RSA PRIVATE KEY-----\n"
      "MIIEpAIBAAKCAQEArcDi8isav4s4la6h1Ix+aUnM11/jiuykvKLVVf48wFZRTcSW\n"
      "c/L0zxRxa8IJQFNm/tnu2BQ1bES0DkdNePc1Z756vR2z20xJ0iwlcgCiJNHBMoIR\n"
      "bDH7oCgagKvDzL/evM5Q4R2OtODjvJ4k1/SiOYJQtW9NZpgZA6U2AN82UYCZtPwy\n"
      "eA9+UOUr3W82PkjgDPUykpB1NTaSWcJ/RAkE8giuV4ukp4J5qecwIheU0UYaeTez\n"
      "uphG5oOesRHVlINQnZLQlhyRNO4az/ptezajfzy7NrwVtNVykgi/mccWTj3bTZT8\n"
      "zcYBMjSosn+4unirlPdRTc2BjEUyGkDDIyCiGQIDAQABAoIBAQCmGXBaRK6LUVHE\n"
      "dW6qu6vUhwJVGYtyMQrCcX8zd5kn3NxYVYfmS+mPVGGgu5sQbSpWkotq8NapK3xc\n"
      "8fiznM7m4AaBZzWafHFNg3pAYy6duA7Sc9in75g14GCFhK3mu7z4DNrweMsFSr8q\n"
      "fpuF/oxeIZ958m6xltDC1VqstrU8bvo/XW2xvMQbL8NyORe7CtawlBZ0WEi4kmW5\n"
      "zwJg+i28qq300PW+i5r6Vab3fbCa2blP6O8vxhA4BTmmOb2sxGYh9X6Y4maSy67L\n"
      "fFGiJEI1s2mvHrJyN/RKAXnZCHMzm+IQtW0+VuTI0uUF2EYqwvvufzAACTX0HU1W\n"
      "DOH8P8apAoGBANUlM/HLlvTM2uPDnh1ZVyVIUZdCGJEFV0LBbSkOc8p8ZKV7Zzb/\n"
      "ELFoFkVcOdGzfywISpTeSMuAkqQDth+oEnGZKjPgM1mKIJkZjzP05+W7ZQdA9neK\n"
      "TK3jsUC3bw1znH7CzmWzj8R6AJAg2pyBMTwbf9FJQChZ47O/S4+zwQ3jAoGBANCw\n"
      "JW4Kww/SKzBzNELb5SUqs2qBz2ezo6jSALxGODlDTiowYSeyOr5BHFWwBM83qF2z\n"
      "lEhANnl8S4nszY+AzVaJcs0EGa6SDkQvoqMX+P7CmhgHW3wdwllN4Dp6rQr0Pw6j\n"
      "9xGsPEnQF7rxa4cOn2ZyNIRkp4p8umMJpEUGjBDTAoGAGZN1QDZlzsomGd6HQo5N\n"
      "3rNm1vefawdxCRmct6h8THfQu+qq3/aLUj5jLb97UKZxRB9ak7J4mbK75eJsIDBS\n"
      "xj7SyZbFkqD4eGaQwHNKwE5UOSKacI2v1c3UnydjtAGDbdKCYcHCJpldJ+5JTS5T\n"
      "chr6o2pewHjI0fDKaFvxdnECgYBv6IWp5QuFSGbwrFayI8lVjPh5fPMD4Uk6FqNe\n"
      "UymDS5x280qmRuVJcREIwkNR+77FwK8br5OGwiif5eS1t5Rle3+cgT5kZt5PolvM\n"
      "qeZUd3a6u/dLL4ow6Zn8whxZa3EFINg1Ge+ahYS0MxI+cpD4FvYiqPdPRGOPCHSW\n"
      "r1QdEQKBgQC0DKAWrAST5Dg3oXPlWk/Y3mc2RvduO4DURROI2Sq6XX9bZP7VEw0m\n"
      "o09ZWv4fN7MMt7Krr3JyMH6UMoIjB+jH+2rXVjHYD5JNQ1mggG5urMc9GdFU1Ph2\n"
      "QgIl2aGiT3LuNRKDmNjazJ5DZwKwlQikfH+lr5SeDLNjbtqhNuYSzQ==\n"
      "-----END RSA PRIVATE KEY-----";
  EXPECT_THAT(PrioSecretKey::ParsePemKey(private_key),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("PEM EC Private Key parsing failed")));
}

// We submit a certificate which is a valid ECDSA certificate, but for the wrong
// curve (P384 instead of P256).
TEST(PrioEncryptionTest, ECDSAP384Certificate) {
  constexpr absl::string_view valid_cert =
      "-----BEGIN CERTIFICATE-----\n"
      "MIICQzCCAcqgAwIBAgIUcJUVbyRBHBk5UlIgwvrTwmVxcO0wCgYIKoZIzj0EAwIw\n"
      "WTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMRMwEQYDVQQKDApHb29nbGUgTExD\n"
      "MSgwJgYJKoZIhvcNAQkBFhlsaWJwcmlvLWNjLWRldkBnb29nbGUuY29tMB4XDTIw\n"
      "MTAyMjIxMzgzMVoXDTIxMTAyMjIxMzgzMVowWTELMAkGA1UEBhMCVVMxCzAJBgNV\n"
      "BAgMAk5ZMRMwEQYDVQQKDApHb29nbGUgTExDMSgwJgYJKoZIhvcNAQkBFhlsaWJw\n"
      "cmlvLWNjLWRldkBnb29nbGUuY29tMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEwDGz\n"
      "JaAUmr0DgXNSN+2fr2Vqpx+/b09uGZnvYLSbJJkBxrRzPZZULM7/c4L0yp9l7LNx\n"
      "W7Px0FVqs6d8MGOS1osI/sLLy80p8uJr4cn5P+toLwAGjIOlyVgxyrexAQFso1Mw\n"
      "UTAdBgNVHQ4EFgQUNlpHpC8g2tqsNXUUAwNlLeeoHiowHwYDVR0jBBgwFoAUNlpH\n"
      "pC8g2tqsNXUUAwNlLeeoHiowDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNn\n"
      "ADBkAjEAh0WI7hin6CcXYUd8WH2TasjjK9g9+Gym8/ZUiZnK8rLawM60a1ifE/qL\n"
      "uFlfDhFmAi80TQCbtd04EB/etiEyxoaCkjtgR/ZiDr7nV+PEpSPR+uKJCGa6dIdD\n"
      "W5YhCxTkqg==\n"
      "-----END CERTIFICATE-----";
  EXPECT_THAT(PrioPublicKey::ParsePemCertificate(valid_cert),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid EC point")));
}

// Submitting a private key for the wrong elliptic curve should fail.
TEST(PrioEncryptionTest, P384PrivateKey) {
  constexpr absl::string_view private_key =
      "-----BEGIN EC PRIVATE KEY-----\n"
      "MIGkAgEBBDBuVAdu4YbORvFSkOMUOlId+EQ5sB3AkFarq2KgxlB20YBNOJqSGGXs\n"
      "C656WqduBGegBwYFK4EEACKhZANiAATm9I2iST7lWeAqHg/WHVsQwwIynDsDOeC7\n"
      "2XQIgFhChOn7+gAS5tweWP/Jz0qyM00QYDSI3+wf3ebo5MT/9gs32cX4aneF86S+\n"
      "4LlQJW0CVo+KtzwhIFTMBEKWQoFeW8s=\n"
      "-----END EC PRIVATE KEY-----";
  EXPECT_THAT(PrioSecretKey::ParsePemKey(private_key),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("scalar has too many bytes, 48")));
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
