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

#include "prio/prng/aes_128_ctr_seeded_prng.h"

#include <cstdint>
#include <iterator>
#include <string>

#include "absl/base/config.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "prio/constants.h"
#include "prio/status_macros.h"
#include "prio/types.h"
#include "prio/util.h"

namespace private_statistics {
namespace prio {

namespace {

const size_t kAes128CtrKeySize = 16;
const size_t kAes128CtrNonceSize = 16;
const size_t kAes128CtrBlockSize = 16;

const size_t kBufferSizeInBlocks = 4096;

// The seed holds both a key and a random nonce, each of which is 16 bytes.
const size_t kAes128CtrSeedSize = kAes128CtrKeySize + kAes128CtrNonceSize;

std::string OpenSSLErrorString() {
  char buf[256];
  ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
  return buf;
}

}  // namespace

size_t Aes128CtrSeededPrng::SeedSize() { return kAes128CtrSeedSize; }

absl::StatusOr<std::string> Aes128CtrSeededPrng::GenerateSeed() {
  std::vector<uint8_t> seed(kAes128CtrSeedSize);
  RAND_bytes(seed.data(), kAes128CtrSeedSize);
  return std::string(std::make_move_iterator(seed.begin()),
                     std::make_move_iterator(seed.end()));
}

absl::StatusOr<std::vector<FieldElement>>
Aes128CtrSeededPrng::GetRandomFieldElementsFromSeed(absl::string_view seed,
                                                    size_t num_elements) {
  if (!internal::IsLittleEndian()) {
    return absl::UnimplementedError(
        "GetRandomFieldElementsFromSeed is not supported on non-little-endian "
        "architectures.");
  }

  if (seed.size() != kAes128CtrSeedSize) {
    return absl::InvalidArgumentError(
        absl::StrCat("seed must be ", kAes128CtrSeedSize,
                     " bytes, supplied seed is ", seed.size(), " bytes."));
  }

  // Split the seed into a key and a nonce.
  std::vector<uint8_t> key(seed.begin(), seed.begin() + kAes128CtrKeySize);
  std::vector<uint8_t> nonce(seed.begin() + kAes128CtrKeySize, seed.end());

  // Create an AES128 key from the supplied seed.
  AES_KEY aes_key;
  if (0 != AES_set_encrypt_key(key.data(), kAes128CtrKeySize * 8, &aes_key)) {
    return absl::InternalError(
        absl::StrCat("AES_set_encrypt_key failed with error message: ",
                     OpenSSLErrorString()));
  }
  unsigned int num = 0;
  std::vector<uint8_t> ecount_buf(AES_BLOCK_SIZE, 0);

  std::vector<FieldElement> output;
  output.reserve(num_elements);

  size_t num_elements_generated = 0;

  // we generate a "buffer" worth of elements at a time, and draw FieldElements
  // from it using rejection sampling. If the buffer runs out, we refill it.
  std::vector<uint8_t> input_to_encrypt(
      kBufferSizeInBlocks * kAes128CtrBlockSize, 0);

  while (num_elements_generated < num_elements) {
    // Reset the buffer.
    std::vector<uint8_t> buffer(kBufferSizeInBlocks * kAes128CtrBlockSize);
    AES_ctr128_encrypt(input_to_encrypt.data(), buffer.data(),
                       kBufferSizeInBlocks * kAes128CtrBlockSize, &aes_key,
                       nonce.data(), ecount_buf.data(), &num);

    // Iterate through the buffer, trying to read off FieldElements.
    size_t position_in_buffer = 0;
    while (position_in_buffer + sizeof(FieldElement) < buffer.size()) {
      FieldElement maybe_element =
          *(reinterpret_cast<FieldElement *>(&buffer[position_in_buffer]));
      position_in_buffer += sizeof(FieldElement);

      if (maybe_element < kPrioModulus) {
        output.push_back(maybe_element);
        num_elements_generated++;
      }

      if (num_elements_generated == num_elements) {
        break;
      }
    }
  }

  return output;
}

}  // namespace prio
}  // namespace private_statistics
