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

#ifndef LIBPRIO_CC_PRIO_TESTING_KEYS_H_
#define LIBPRIO_CC_PRIO_TESTING_KEYS_H_

#include <array>

#include "absl/strings/string_view.h"

namespace private_statistics {
namespace prio {
namespace testing {

struct KeyMaterial {
  const absl::string_view certificate;
  const absl::string_view secret_key;
};

constexpr std::array<KeyMaterial, 2> PemKeys{
    KeyMaterial{.certificate = R"(-----BEGIN CERTIFICATE-----
MIIB4DCCAYegAwIBAgIUZ5cOgeyroHDM+X/AMwt5Oc2X1hYwCgYIKoZIzj0EAwIw
RjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQ8wDQYDVQQKDAZHb29nbGUxGTAX
BgNVBAMMEEZhY2lsaXRhdG9yIFByaW8wHhcNMjAwOTEyMjM1MTAwWhcNMjEwOTEy
MjM1MTAwWjBGMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTlkxDzANBgNVBAoMBkdv
b2dsZTEZMBcGA1UEAwwQRmFjaWxpdGF0b3IgUHJpbzBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABJG9n+Xm562rBGfKeDvOWlWcH2EkmkJVVfuxJeIdA62Tkl1RkMZ1
h8QRnY81vPq7EfbwzRR2ZbErfrJ6hGYE1DujUzBRMB0GA1UdDgQWBBQVLuXyDZBU
NLN7iCAefbnJJvnXFDAfBgNVHSMEGDAWgBQVLuXyDZBUNLN7iCAefbnJJvnXFDAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCICclmF8PdAjwc/9oEkOu
FaUI2JrRAmg/kfpNuhCdF45KAiB6Wmv+Dfu04UECTC0pDAVisH1FamkDOnbCO7PF
9BVmNg==
-----END CERTIFICATE-----)",
                .secret_key = R"(-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINoZSsrWzMmXe1UYYIpH3g4TOKqHReMpaB8dMLSC4trJoAoGCCqGSM49
AwEHoUQDQgAEkb2f5ebnrasEZ8p4O85aVZwfYSSaQlVV+7El4h0DrZOSXVGQxnWH
xBGdjzW8+rsR9vDNFHZlsSt+snqEZgTUOw==
-----END EC PRIVATE KEY-----
)"},
    KeyMaterial{.certificate = R"(-----BEGIN CERTIFICATE-----
MIIB0jCCAXmgAwIBAgIUWZ0NdCD482eUR9HeTDXPhMEKCxMwCgYIKoZIzj0EAwIw
PzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMQ8wDQYDVQQKDAZHb29nbGUxEjAQ
BgNVBAMMCU1haW4gUHJpbzAeFw0yMDA5MTIyMzUxNDdaFw0yMTA5MTIyMzUxNDda
MD8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJOWTEPMA0GA1UECgwGR29vZ2xlMRIw
EAYDVQQDDAlNYWluIFByaW8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATj+o78
HMgY7//f8j2HYxbLE4s3v28JwjbARl5QE8z/FogXX2zoyH6aqAaZl78rLKTQH2aV
iIuofMfkTgbbfDIeo1MwUTAdBgNVHQ4EFgQUE0RDdVvf7GXQDMqg1+ehAWrWRWow
HwYDVR0jBBgwFoAUE0RDdVvf7GXQDMqg1+ehAWrWRWowDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNHADBEAiB2TzEPdU7RCmNEpC3aLRtxyj2DiwC1MRqHYt42
5VNJ3QIgCxN/3RpETjrc8dFcIgdxkFZNrWr2A3sheinLb0lhTFo=
-----END CERTIFICATE-----)",
                .secret_key = R"(-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGVR00iBQBWWpVyMwgFiLOS+rKivGIXxw4kuFoxoMey7oAoGCCqGSM49
AwEHoUQDQgAE4/qO/BzIGO//3/I9h2MWyxOLN79vCcI2wEZeUBPM/xaIF19s6Mh+
mqgGmZe/Kyyk0B9mlYiLqHzH5E4G23wyHg==
-----END EC PRIVATE KEY-----
)"}};

}  // namespace testing
}  // namespace prio
}  // namespace private_statistics

#endif  // LIBPRIO_CC_PRIO_TESTING_KEYS_H_
