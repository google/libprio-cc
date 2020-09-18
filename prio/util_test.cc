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

#include "prio/util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "prio/testing/status_matchers.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {
namespace {

using internal::NextPowerTwo;
using internal::NextPowerTwoMinusOne;
using testing::StatusIs;

template <typename Uint>
class UtilTest : public ::testing::Test {};
using TestTypes = ::testing::Types<uint8_t, uint16_t, FieldElement, uint64_t>;
TYPED_TEST_SUITE(UtilTest, TestTypes);

TYPED_TEST(UtilTest, NextPowerTwoMinusOne) {
  using Uint = TypeParam;

  // NextPowerTwoMinusOne(0) = 2^0-1 = 0.
  EXPECT_EQ(NextPowerTwoMinusOne<Uint>(0), 0);

  // NextPowerTwoMinusOne(2^i) = 2^(i+1) - 1 for all 0 <= i <=
  // 8*sizeof(Uint)-2.
  for (size_t i = 1; i < 8 * sizeof(Uint); i++) {
    Uint u = static_cast<Uint>(1) << (i - 1);
    EXPECT_EQ(NextPowerTwoMinusOne<Uint>(u), (u << 1) - 1);
  }

  // NextPowerTwoMinusOne(2^i) = 2^(i+1) - 1 for i = 8*sizeof(Uint)-1.
  {
    Uint u = static_cast<Uint>(1) << (8 * sizeof(Uint) - 1);
    EXPECT_EQ(NextPowerTwoMinusOne<Uint>(u), static_cast<Uint>(-1));
  }

  // NextPowerTwoMinusOne(2^i - 1) = 2^i - 1 for all 0 <= i <=
  // 8*sizeof(Uint)-1.
  for (size_t i = 1; i < 8 * sizeof(Uint); i++) {
    Uint u = (static_cast<Uint>(1) << i) - 1;
    EXPECT_EQ(NextPowerTwoMinusOne<Uint>(u), u);
  }
}

TYPED_TEST(UtilTest, NextPowerTwo) {
  using Uint = TypeParam;

  // NextPowerTwo(0) = 1
  PRIO_ASSERT_OK_AND_ASSIGN(Uint v, NextPowerTwo<Uint>(0));
  EXPECT_EQ(v, 1);

  // NextPowerTwo(2^i) = 2^i for all 0 <= i <= 8*sizeof(Uint)-1.
  for (size_t i = 0; i < 8 * sizeof(Uint); i++) {
    Uint u = static_cast<Uint>(1) << i;
    PRIO_ASSERT_OK_AND_ASSIGN(v, NextPowerTwo<Uint>(u));
    EXPECT_EQ(u, v);
  }

  // NextPowerTwo(2^i+1) = 2^(i+1) for all 0 <= i <= 8*sizeof(Uint)-2.
  for (size_t i = 0; i < 8 * sizeof(Uint) - 1; i++) {
    Uint u = (static_cast<Uint>(1) << i) + 1;
    PRIO_ASSERT_OK_AND_ASSIGN(v, NextPowerTwo<Uint>(u));
    EXPECT_EQ(v, (static_cast<Uint>(1) << (i + 1)));
  }

  // NextPowerTwo(2^i + 1) raises an error for i = 8*sizeof(Uint)-1.
  {
    Uint u = (static_cast<Uint>(1) << (8 * sizeof(Uint) - 1)) + 1;
    EXPECT_THAT(NextPowerTwo<Uint>(u),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         ::testing::HasSubstr("does not fit")));
  }
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
