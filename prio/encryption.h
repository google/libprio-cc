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

#ifndef PRIVATE_ANALYTICS_PRIO_ENCRYPTION_H_
#define PRIVATE_ANALYTICS_PRIO_ENCRYPTION_H_

#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "prio/status_macros.h"

namespace private_statistics {
namespace prio {

namespace internal {
// Elliptic curve constants. The encryption scheme uses curve P256, the public
// keys are in uncompressed X9.62 format, and the secret are the concatenation
// of the public key and a 32-byte scalar.
const size_t kPublicKeyLength = 65;
const size_t kSecretKeyLength = kPublicKeyLength + 32;
// Constants for AES-GCM. We use AES128, with 16-byte tags and 16-bytes IV.
const size_t kTagLength = 16;
const size_t kAesKeyLength = 16;
const size_t kIvLength = 16;

// Utility function to transform a uint32_t into a vector of bytes in big endian
// representation.
std::vector<uint8_t> Uint32ToBigEndianBytes(uint32_t x);

// An implementation of the X9.63 KDF using SHA256 and outputtting exactly 32
// bytes.
std::string X963KdfOutputs32Bytes(absl::string_view shared_secret,
                                  absl::string_view shared_info);

}  // namespace internal

// Class that holds a public key for use in Prio, and consists of a point on the
// elliptic curve P-256. The public key can be parsed from a PEM elliptic curve
// certificate over P-256, or from the base64 uncompressed X9.62 representation
// of the elliptic curve point.
class PrioPublicKey {
 public:
  // Factory function to create a public key from a X509 certificate, in PEM
  // format.
  static absl::StatusOr<PrioPublicKey> ParsePemCertificate(
      absl::string_view certificate_pem);
  // Factory function to create a public key from its uncompressed X9.62
  // representation, given in base 64.
  static absl::StatusOr<PrioPublicKey> ParseANSIX962Base64(
      absl::string_view public_key);
  // Factory function to create a secret key from the full base 64
  // representation of the uncompressed X9.62 representation concatenated with
  // the secret key scalar.
  static absl::StatusOr<PrioPublicKey> ParseFullKeyBase64(
      absl::string_view full_key);
  // Accessor.
  EC_POINT* Get() const { return ec_point_.get(); }

 private:
  explicit PrioPublicKey(bssl::UniquePtr<EC_POINT> ec_point)
      : ec_point_(std::move(ec_point)) {}
  bssl::UniquePtr<EC_POINT> ec_point_;
};

// Class that holds a secret key for use in Prio, which is a 32-byte scalar that
// is used to create a public key (elliptic curve point) from the default
// generator on P-256. The secret key can be parsed from a PEM key file or from
// the base64 representation of the scalar, or from the base64 representation of
// the full key, which is the representation of the uncompressed X9.62
// representation concatenated with the scalar.
class PrioSecretKey {
 public:
  // Factory function to create a secret key from its PEM representation.
  static absl::StatusOr<PrioSecretKey> ParsePemKey(absl::string_view key_pem);
  // Factory function to create a secret key from the base 64 representation
  // of the scalar.
  static absl::StatusOr<PrioSecretKey> ParseScalar(absl::string_view scalar);
  // Factory function to create a secret key from the full base 64
  // representation of the uncompressed X9.62 representation concatenated with
  // the scalar.
  static absl::StatusOr<PrioSecretKey> ParseFullKeyBase64(
      absl::string_view full_key);
  // Accessor.
  BIGNUM* Get() const { return scalar_.get(); }

 private:
  explicit PrioSecretKey(bssl::UniquePtr<BIGNUM> scalar)
      : scalar_(std::move(scalar)) {}
  bssl::UniquePtr<BIGNUM> scalar_;
};

// This class implements the ECIES Encryption Standard over P-256, with Variable
// IV, and uses the ANSI X9.63 key derivation function with SHA-256 as the hash
// function, and finally uses AES128-GCM for the payload.
//
// This is necessary for interoperability with the
//     kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM
// as implemented in the Apple Security framework.
class PrioEncryption {
 public:
  // Static function to encrypt a non-empty payload, given an EC public key
  // (X9.62 format). The output is encoded in basee 64.
  //
  // This function returns kInvalidArgument errors if the arguments are not
  // properly formatted, and may return kInternal errors if cryptographic errors
  // occur.
  static absl::StatusOr<std::string> Encrypt(const PrioPublicKey& pk,
                                             absl::string_view payload);

  // Static function to decrypt an encrypted payload in base 64 with the secret
  // key.
  //
  // This function returns kInvalidArgument errors if the arguments are not
  // properly formatted, and may return kInternal errors if cryptographic errors
  // occur.
  static absl::StatusOr<std::string> Decrypt(
      const PrioSecretKey& sk, absl::string_view encrypted_payload);
};

}  // namespace prio
}  // namespace private_statistics

#endif  // PRIVATE_ANALYTICS_PRIO_ENCRYPTION_H_
