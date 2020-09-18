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

#include <iterator>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include "prio/status_macros.h"
#include "prio/util.h"

namespace private_statistics {
namespace prio {
namespace internal {

#ifdef ABSL_IS_LITTLE_ENDIAN
std::vector<uint8_t> Uint32ToBigEndianBytes(uint32_t x) {
  x = absl::gbswap_32(x);  // Swap the bit representation of x.
  std::vector<uint8_t> output(4);
  output[0] = x;
  output[1] = x >> 8;
  output[2] = x >> 16;
  output[3] = x >> 24;
  return output;
}
#elif defined ABSL_IS_BIG_ENDIAN
std::vector<uint8_t> Uint32ToBigEndianBytes(uint32_t x) {
  std::vector<uint8_t> output(4);
  output[0] = x >> 24;
  output[1] = x >> 16;
  output[2] = x >> 8;
  output[3] = x;
  return output;
}
#endif /* ENDIAN */

std::string X963KdfOutputs32Bytes(absl::string_view shared_secret,
                                  absl::string_view shared_info) {
  // Sec 3.6.1 of https://www.secg.org/sec1-v2.pdf.
  std::vector<uint8_t> counter_bytes = internal::Uint32ToBigEndianBytes(1);

  // Construct the input.
  std::string input;
  input.reserve(shared_secret.size() + counter_bytes.size() +
                shared_info.size());
  input.append(shared_secret.begin(), shared_secret.end());
  input.append(counter_bytes.begin(), counter_bytes.end());
  input.append(shared_info.begin(), shared_info.end());

  // Compute the SHA256 of the input.
  std::vector<uint8_t> output(32, 0);
  SHA256(reinterpret_cast<const uint8_t *>(input.data()), input.size(),
         output.data());
  return std::string(std::make_move_iterator(output.begin()),
                     std::make_move_iterator(output.end()));
}

// Get elliptic curve group.
absl::StatusOr<bssl::UniquePtr<EC_GROUP>> GetEcGroup() {
  bssl::UniquePtr<EC_GROUP> ec_group(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  if (ec_group == nullptr) {
    return absl::InternalError("Cryptographic error when getting the group.");
  }
  return std::move(ec_group);
}

// Specialization of crypto::tink::subtle::SubtleUtilBoringSSL::EcPointDecode(),
// from Tink, which is not publicly visible. We specialize it by assuming that
// the point is in format EcPointFormat::UNCOMPRESSED.
absl::StatusOr<bssl::UniquePtr<EC_POINT>> EcPointDecode(
    EC_GROUP *ec_group, absl::string_view encoded) {
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(ec_group));
  unsigned curve_size_in_bytes = (EC_GROUP_get_degree(ec_group) + 7) / 8;
  if (static_cast<int>(encoded[0]) != 0x04) {
    return absl::InternalError(
        "Uncompressed point should start with 0x04, but input doesn't");
  }
  if (encoded.size() != 1 + 2 * curve_size_in_bytes) {
    return absl::InternalError(
        absl::Substitute("point has is $0 bytes, expected $1", encoded.size(),
                         1 + 2 * curve_size_in_bytes));
  }
  if (1 != EC_POINT_oct2point(ec_group, point.get(),
                              reinterpret_cast<const uint8_t *>(encoded.data()),
                              encoded.size(), nullptr)) {
    return absl::InternalError("EC_POINT_toc2point failed");
  }
  if (1 != EC_POINT_is_on_curve(ec_group, point.get(), nullptr)) {
    return absl::InternalError("Point is not on curve");
  }
  return {std::move(point)};
}

// Specialization of crypto::tink::subtle::SubtleUtilBoringSSL::EcPointEncode(),
// from Tink, which is not publicly visible. We specialize it by assuming that
// the point is in format EcPointFormat::UNCOMPRESSED.
absl::StatusOr<std::string> EcPointEncode(EC_GROUP *ec_group,
                                          const EC_POINT *point) {
  unsigned curve_size_in_bytes = (EC_GROUP_get_degree(ec_group) + 7) / 8;
  if (1 != EC_POINT_is_on_curve(ec_group, point, nullptr)) {
    return absl::InternalError("Point is not on curve");
  }
  std::unique_ptr<uint8_t[]> encoded(new uint8_t[1 + 2 * curve_size_in_bytes]);
  size_t size =
      EC_POINT_point2oct(ec_group, point, POINT_CONVERSION_UNCOMPRESSED,
                         encoded.get(), 1 + 2 * curve_size_in_bytes, nullptr);
  if (size != 1 + 2 * curve_size_in_bytes) {
    return absl::InternalError("EC_POINT_point2oct failed");
  }
  return std::string(reinterpret_cast<const char *>(encoded.get()),
                     1 + 2 * curve_size_in_bytes);
}

// Specialization of FieldElementSizeInBytes and
// SubtleUtilBoringSSL::BignumToSecretData which are not publicly visible.
size_t FieldElementSizeInBytes(const EC_GROUP *group) {
  unsigned degree_bits = EC_GROUP_get_degree(group);
  return (degree_bits + 7) / 8;
}

absl::StatusOr<std::string> BignumToSecretData(const BIGNUM *bn, size_t len) {
  if (bn == nullptr) {
    return absl::InvalidArgumentError("BIGNUM is NULL");
  }
  std::vector<uint8_t> res(len);
  if (BN_bn2bin_padded(res.data(), res.size(), bn) != 1) {
    return absl::InternalError("Value too large");
  }
  return std::string(std::make_move_iterator(res.begin()),
                     std::make_move_iterator(res.end()));
}

// Specialization of
// crypto::tink::subtle::SubtleUtilBoringSSL::ComputeEcdhSharedSecret which is
// not publicly visible.
absl::StatusOr<std::string> ComputeEcdhSharedSecret(EC_GROUP *ec_group,
                                                    const BIGNUM *priv_key,
                                                    const EC_POINT *pub_key) {
  bssl::UniquePtr<EC_POINT> shared_point(EC_POINT_new(ec_group));
  // BoringSSL's EC_POINT_set_affine_coordinates_GFp documentation says that
  // "unlike with OpenSSL, it's considered an error if the point is not on the
  // curve". To be sure, we double check here.
  if (1 != EC_POINT_is_on_curve(ec_group, pub_key, nullptr)) {
    return absl::InternalError("Point is not on curve");
  }
  // Compute the shared point.
  if (1 != EC_POINT_mul(ec_group, shared_point.get(), nullptr, pub_key,
                        priv_key, nullptr)) {
    return absl::InternalError("Point multiplication failed");
  }
  // Check for buggy computation.
  if (1 != EC_POINT_is_on_curve(ec_group, shared_point.get(), nullptr)) {
    return absl::InternalError("Shared point is not on curve");
  }
  // Get shared point's x coordinate.
  bssl::UniquePtr<BIGNUM> shared_x(BN_new());
  if (1 != EC_POINT_get_affine_coordinates_GFp(ec_group, shared_point.get(),
                                               shared_x.get(), nullptr,
                                               nullptr)) {
    return absl::InternalError("EC_POINT_get_affine_coordinates_GFp failed");
  }
  return BignumToSecretData(shared_x.get(), FieldElementSizeInBytes(ec_group));
}

}  // namespace internal

absl::StatusOr<std::string> PrioEncryption::Encrypt(const PrioPublicKey &pk,
                                                    absl::string_view payload) {
  // The following code follows the blueprint used in
  //   tink/cc/subtle/ecies_hkdf_sender_kem_boringssl.cc
  // for the ECDH key exchange, and mimicks
  //   tink/cc/aead/internal/cord_aes_gcm_boringssl.cc
  // for AES-GCM encryption.
  // Get elliptic curve group.
  PRIO_ASSIGN_OR_RETURN(bssl::UniquePtr<EC_GROUP> ec_group,
                        internal::GetEcGroup());

  // Generate an ephemeral key pair.
  bssl::UniquePtr<EC_KEY> ephemeral_key(EC_KEY_new());
  if (1 != EC_KEY_set_group(ephemeral_key.get(), ec_group.get())) {
    return absl::InternalError("EC_KEY_set_group failed");
  }
  if (1 != EC_KEY_generate_key(ephemeral_key.get())) {
    return absl::InternalError("EC_KEY_generate_key failed");
  }
  const BIGNUM *ephemeral_priv = EC_KEY_get0_private_key(ephemeral_key.get());
  const EC_POINT *ephemeral_pub = EC_KEY_get0_public_key(ephemeral_key.get());

  // Encode the ephemeral public key.
  PRIO_ASSIGN_OR_RETURN(std::string kem_bytes,
                        internal::EcPointEncode(ec_group.get(), ephemeral_pub));

  // Compute ECDH shared secret.
  PRIO_ASSIGN_OR_RETURN(auto shared_secret,
                        internal::ComputeEcdhSharedSecret(
                            ec_group.get(), ephemeral_priv, pk.Get()));

  // Call the KDF. The shared information (second parameter) is kem_bytes, which
  // currently contains the serialized ephemeral_pub.
  std::string kdf_output =
      internal::X963KdfOutputs32Bytes(shared_secret, kem_bytes);

  // Encrypt using AES-GCM.
  absl::string_view key(kdf_output.data(), internal::kAesKeyLength);
  absl::string_view iv(kdf_output.data() + internal::kAesKeyLength,
                       internal::kIvLength);
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr,
                          nullptr)) {
    return absl::InternalError("Encryption init failed");
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           internal::kIvLength, nullptr)) {
    return absl::InternalError("Setting IV size failed");
  }

  if (!EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                          reinterpret_cast<const uint8_t *>(key.data()),
                          reinterpret_cast<const uint8_t *>(iv.data()))) {
    return absl::InternalError("Encryption init failed");
  }

  // Encrypt.
  int len = 0;
  std::vector<uint8_t> ciphertext(payload.size());
  if (!EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                         reinterpret_cast<const uint8_t *>(payload.data()),
                         payload.size())) {
    return absl::InternalError("Encryption update failed");
  }

  if (!EVP_EncryptFinal_ex(ctx.get(), nullptr, &len)) {
    return absl::InternalError("Encryption failed");
  }

  std::vector<uint8_t> tag(internal::kTagLength);
  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                           internal::kTagLength, tag.data())) {
    return absl::InternalError("Tag generation failed");
  }

  // Concatenate the ciphertext and tag to kem_bytes (which already contains the
  // serialized ephemeral_pub) and output the result.
  std::string encrypted_payload =
      kem_bytes +
      std::string(std::make_move_iterator(ciphertext.begin()),
                  std::make_move_iterator(ciphertext.end())) +
      std::string(std::make_move_iterator(tag.begin()),
                  std::make_move_iterator(tag.end()));
  return absl::Base64Escape(encrypted_payload);
}

absl::StatusOr<std::string> PrioEncryption::Decrypt(const PrioSecretKey &sk,
                                                    absl::string_view payload) {
  // The following code follows the blueprint used in
  //   tink/cc/subtle/ecies_hkdf_receiver_kem_boringssl.cc
  // for the ECDH key exchange, and mimicks
  //   tink/cc/aead/internal/cord_aes_gcm_boringssl.cc
  // for AES-GCM decryption.
  std::string payload_decoded;
  if (!absl::Base64Unescape(payload, &payload_decoded)) {
    return absl::InvalidArgumentError("The payload cannot be decoded.");
  }
  if (payload_decoded.size() <
      internal::kPublicKeyLength + internal::kTagLength) {
    return absl::InvalidArgumentError("The payload is invalid.");
  }

  // Parse the payload.
  std::string ephemeral_public_key(
      payload_decoded.begin(),
      payload_decoded.begin() + internal::kPublicKeyLength);
  std::string ciphertext(payload_decoded.begin() + internal::kPublicKeyLength,
                         payload_decoded.end() - internal::kTagLength);
  std::vector<uint8_t> tag(
      payload_decoded.begin() + (payload_decoded.size() - internal::kTagLength),
      payload_decoded.end());

  // Get elliptic curve group.
  PRIO_ASSIGN_OR_RETURN(bssl::UniquePtr<EC_GROUP> ec_group,
                        internal::GetEcGroup());

  // Generate the shared secret string.
  PRIO_ASSIGN_OR_RETURN(
      bssl::UniquePtr<EC_POINT> pub_key,
      internal::EcPointDecode(ec_group.get(), ephemeral_public_key));
  PRIO_ASSIGN_OR_RETURN(auto shared_secret,
                        internal::ComputeEcdhSharedSecret(
                            ec_group.get(), sk.Get(), pub_key.get()));

  // Call the KDF.
  std::string kdf_output =
      internal::X963KdfOutputs32Bytes(shared_secret, ephemeral_public_key);

  // Decrypt using AES-GCM.
  absl::string_view key(kdf_output.data(), internal::kAesKeyLength);
  absl::string_view iv(kdf_output.data() + internal::kAesKeyLength,
                       internal::kIvLength);
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (!EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr,
                          nullptr)) {
    return absl::InternalError("Decryption init failed");
  }

  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           internal::kIvLength, nullptr)) {
    return absl::InternalError("Setting IV size failed");
  }

  if (!EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                          reinterpret_cast<const uint8_t *>(key.data()),
                          reinterpret_cast<const uint8_t *>(iv.data()))) {
    return absl::InternalError("Decryption init failed");
  }

  int len = 0;
  std::vector<uint8_t> plaintext(ciphertext.size());
  if (!EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                         reinterpret_cast<const uint8_t *>(ciphertext.data()),
                         ciphertext.size())) {
    return absl::InternalError("Decryption failed");
  }

  // Verify authentication tag
  if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                           internal::kTagLength,
                           reinterpret_cast<void *>(tag.data()))) {
    return absl::InternalError("Could not set authentication tag");
  }

  if (!EVP_DecryptFinal_ex(ctx.get(), nullptr, &len)) {
    return absl::InternalError("Authentication failed");
  }

  return std::string(std::make_move_iterator(plaintext.begin()),
                     std::make_move_iterator(plaintext.end()));
}

absl::StatusOr<PrioPublicKey> PrioPublicKey::ParseANSIX962Base64(
    absl::string_view public_key) {
  // Decode.
  std::string public_key_decoded;
  if (!absl::Base64Unescape(public_key, &public_key_decoded)) {
    return absl::InvalidArgumentError("Invalid encoding.");
  }

  // Get elliptic curve group.
  PRIO_ASSIGN_OR_RETURN(bssl::UniquePtr<EC_GROUP> ec_group,
                        internal::GetEcGroup());

  // Parse using Tink.
  PRIO_ASSIGN_OR_RETURN(
      bssl::UniquePtr<EC_POINT> ec_point,
      internal::EcPointDecode(ec_group.get(), public_key_decoded));
  return PrioPublicKey(std::move(ec_point));
}

absl::StatusOr<PrioPublicKey> PrioPublicKey::ParseFullKeyBase64(
    absl::string_view full_key) {
  // Decode.
  std::string full_key_decoded;
  if (!absl::Base64Unescape(full_key, &full_key_decoded)) {
    return absl::InvalidArgumentError("Invalid encoding.");
  }

  // Check that the full_key is properly formatted.
  if (full_key_decoded.size() != internal::kSecretKeyLength) {
    return absl::InvalidArgumentError(
        "The full_key is invalid: it should be the concatenation of the "
        "public key and the full_key representing the secret key.");
  }

  // Extract the value from the full_key_decoded.
  absl::string_view public_key(full_key_decoded.data(),
                               internal::kPublicKeyLength);

  // Get elliptic curve group.
  PRIO_ASSIGN_OR_RETURN(bssl::UniquePtr<EC_GROUP> ec_group,
                        internal::GetEcGroup());

  // Parse using Tink.
  PRIO_ASSIGN_OR_RETURN(bssl::UniquePtr<EC_POINT> ec_point,
                        internal::EcPointDecode(ec_group.get(), public_key));
  return PrioPublicKey(std::move(ec_point));
}

absl::StatusOr<PrioPublicKey> PrioPublicKey::ParsePemCertificate(
    absl::string_view certificate) {
  // Put the certificate contents into a BoringSSL IO stream (BIO)
  bssl::UniquePtr<BIO> cert_bio(BIO_new(BIO_s_mem()));
  if (cert_bio == nullptr) {
    return absl::InternalError("Internal cryptographic error.");
  }
  if (BIO_write(cert_bio.get(), certificate.data(), certificate.size()) < 0) {
    return absl::InternalError("Internal cryptographic error.");
  }
  // Create a BoringSSL certificate from the BIO.
  bssl::UniquePtr<X509> cert(PEM_read_bio_X509_AUX(
      cert_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (cert == nullptr) {
    return absl::InvalidArgumentError(
        "PEM Certificate parsing failed: cannot be parsed by BoringSSL");
  }

  // Extract the public key.
  bssl::UniquePtr<EVP_PKEY> evp_pkey(X509_get_pubkey(cert.get()));
  bssl::UniquePtr<EC_KEY> ec_key(EVP_PKEY_get1_EC_KEY(evp_pkey.get()));
  const EC_POINT *ec_point = EC_KEY_get0_public_key(ec_key.get());
  if (ec_point == nullptr) {
    return absl::InvalidArgumentError(
        "PEM Certificate parsing failed: wrong key type?");
  }

  // Get elliptic curve group.
  PRIO_ASSIGN_OR_RETURN(bssl::UniquePtr<EC_GROUP> ec_group,
                        internal::GetEcGroup());

  // Copy the EC_POINT into the output.
  bssl::UniquePtr<EC_POINT> pk(EC_POINT_new(ec_group.get()));
  if (pk == nullptr) {
    return absl::InternalError("Internal cryptographic error.");
  }
  EC_POINT_copy(pk.get(), ec_point);
  return PrioPublicKey(std::move(pk));
}

absl::StatusOr<PrioSecretKey> PrioSecretKey::ParsePemKey(
    absl::string_view key_pem) {
  // Read the private key into EC_KEY, using BoringSSL APIs to parse the PEM
  // data.
  bssl::UniquePtr<BIO> ec_key_bio(BIO_new(BIO_s_mem()));
  if (ec_key_bio == nullptr) {
    return absl::InternalError("Internal cryptographic error.");
  }
  if (BIO_write(ec_key_bio.get(), key_pem.data(), key_pem.size()) < 0) {
    return absl::InternalError("Internal cryptographic error.");
  }
  bssl::UniquePtr<EC_KEY> ec_key(PEM_read_bio_ECPrivateKey(
      ec_key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (ec_key == nullptr) {
    return absl::InvalidArgumentError("PEM Private Key parsing failed");
  }

  const BIGNUM *priv_key = EC_KEY_get0_private_key(ec_key.get());
  if (priv_key == nullptr) {
    return absl::InvalidArgumentError("PEM Private Key parsing failed");
  }

  // Copy the BIGNUM into the output.
  bssl::UniquePtr<BIGNUM> sk(BN_new());
  BN_copy(sk.get(), priv_key);
  return PrioSecretKey(std::move(sk));
}

absl::StatusOr<PrioSecretKey> PrioSecretKey::ParseFullKeyBase64(
    absl::string_view full_key) {
  // Decode.
  std::string full_key_decoded;
  if (!absl::Base64Unescape(full_key, &full_key_decoded)) {
    return absl::InvalidArgumentError("Invalid encoding.");
  }

  // Check that the full_key is properly formatted.
  if (full_key_decoded.size() != internal::kSecretKeyLength) {
    return absl::InvalidArgumentError(
        "The full_key is invalid: it should be the concatenation of the "
        "public key and the full_key representing the secret key.");
  }

  // Extract the value from the full_key_decoded.
  absl::string_view scalar(
      full_key_decoded.data() + internal::kPublicKeyLength,
      internal::kSecretKeyLength - internal::kPublicKeyLength);
  return ParseScalar(scalar);
}

absl::StatusOr<PrioSecretKey> PrioSecretKey::ParseScalar(
    absl::string_view scalar) {
  if (scalar.size() !=
      internal::kSecretKeyLength - internal::kPublicKeyLength) {
    return absl::InvalidArgumentError("The scalar is invalid.");
  }
  bssl::UniquePtr<BIGNUM> priv_key(
      BN_bin2bn(reinterpret_cast<const uint8_t *>(scalar.data()), scalar.size(),
                nullptr));
  return PrioSecretKey(std::move(priv_key));
}

}  // namespace prio
}  // namespace private_statistics
