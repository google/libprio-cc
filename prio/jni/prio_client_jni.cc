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

#include <jni.h>
#include <string.h>
#include <sys/syslog.h>
#include <syslog.h>

#include <random>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "prio/client.h"
#include "prio/encryption.h"
#include "prio/jni/message.pb.h"

namespace private_statistics {
namespace prio {
namespace {

// Deserializes the proto message from the input jbyteArray.
bool BytesToCppProto(JNIEnv* env, google::protobuf::MessageLite* proto,
                     jbyteArray input) {
  bool parsed_ok = false;
  const int size = env->GetArrayLength(input);
  void* ptr = env->GetPrimitiveArrayCritical(input, nullptr);
  if (ptr) {
    parsed_ok = proto->ParseFromArray(reinterpret_cast<char*>(ptr), size);
    env->ReleasePrimitiveArrayCritical(input, ptr, JNI_ABORT);
  }
  return parsed_ok;
}

// Serializes the proto message into jbyteArray.
jbyteArray CppProtoToBytes(JNIEnv* env, const google::protobuf::MessageLite& proto) {
  size_t size = proto.ByteSizeLong();
  jbyteArray ret = env->NewByteArray(size);
  if (ret == nullptr) {
    syslog(LOG_CRIT,
           "CppProtoToBytes: Failed to allocate space for return value");
    return nullptr;
  }
  uint8_t* ret_buf =
      static_cast<uint8_t*>(env->GetPrimitiveArrayCritical(ret, nullptr));
  proto.SerializeWithCachedSizesToArray(ret_buf);
  env->ReleasePrimitiveArrayCritical(ret, ret_buf, 0);
  return ret;
}

absl::StatusOr<std::vector<std::string>> CreateEncryptedShares(
    proto::CreatePacketsParameters params) {
  if (!params.has_prio_parameters()) {
    return absl::InvalidArgumentError(
        "The CreatePacketsParameters does not have PrioAlgorithmParameters.");
  }

  if (!params.prio_parameters().has_number_servers()) {
    return absl::InvalidArgumentError(
        "The number of servers is not specified.");
  }

  if (params.public_keys_size() != params.prio_parameters().number_servers()) {
    return absl::InvalidArgumentError(
        "The number of public keys does not match the number of servers "
        "specified in the parameters.");
  }

  // Create the vectors of public keys.
  std::vector<std::string> public_keys;
  public_keys.reserve(params.public_keys_size());
  for (absl::string_view public_key : params.public_keys()) {
    public_keys.emplace_back(public_key);
  }

  // Create client's output.
  auto client = Client::Create(params.prio_parameters(), public_keys);
  std::vector<uint32_t> data_bits =
      std::vector<uint32_t>(std::make_move_iterator(params.data_bits().begin()),
                            std::make_move_iterator(params.data_bits().end()));
  return client->ProcessInput(std::move(data_bits));
}

extern "C" jbyteArray
Java_com_google_android_apps_exposurenotification_privateanalytics_PrioJni_createPackets(
    JNIEnv* env, jclass clazz, jbyteArray input_bytes_params_bytes) {
  proto::CreatePacketsParameters params;
  proto::CreatePacketsResponse response;

  if (!BytesToCppProto(env, &params, input_bytes_params_bytes)) {
    response.mutable_response_status()->set_status_code(
        proto::ResponseStatus::INVALID_PARAMETER_FAILURE);
    response.mutable_response_status()->set_error_details(
        "Error parsing params from bytes");
    return CppProtoToBytes(env, response);
  }

  const absl::StatusOr<std::vector<std::string>>& encrypted_shares =
      CreateEncryptedShares(params);

  if (!encrypted_shares.ok()) {
    response.mutable_response_status()->set_status_code(
        proto::ResponseStatus::UNKNOWN_FAILURE);
    response.mutable_response_status()->set_error_details(
        std::string(encrypted_shares.status().message()));
    // Return as serialized bytes
    return CppProtoToBytes(env, response);
  }

  for (size_t i = 0; i < encrypted_shares->size(); i++) {
    response.add_share(encrypted_shares->at(i));
  }
  response.mutable_response_status()->set_status_code(
      proto::ResponseStatus::OK);

  return CppProtoToBytes(env, response);
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
