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

#ifndef PRIVATE_ANALYTICS_PRIO_CONSTANTS_H_
#define PRIVATE_ANALYTICS_PRIO_CONSTANTS_H_

#include "prio/types.h"

namespace private_statistics {
namespace prio {

// 2^32 - 2^20 + 1, a "nice" prime modulus that will allow FFT, while fitting
// within a uint32_t.
static const FieldElement kPrioModulus = 4293918721;
// Fixed generator for the field of integers mod kPrioModulus.
static const FieldElement kPrioGenerator = 3925978153;
// Number of Primitive roots of unity to use in polynomial FFT.
static const int kPrioNumRoots = 1 << 20;

// Local differential privacy added before aggregation.
// LINT.IfChange(default_epsilon)
static const double kDefaultEpsilon = 12.0;
// LINT.ThenChange(//depot/google3/third_party/private_statistics/prio/proto/algorithm_parameters.proto:default_epsilon)

// Default number of servers.
static const int kDefaultNumberOfServers = 2;

}  // namespace prio
}  // namespace private_statistics

#endif  // PRIVATE_ANALYTICS_PRIO_CONSTANTS_H_
