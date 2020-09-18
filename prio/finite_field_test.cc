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

#include "prio/finite_field.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "prio/constants.h"
#include "prio/testing/status_matchers.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {
namespace {

using ::testing::HasSubstr;
using testing::StatusIs;

TEST(FiniteFieldTest, SubMod) {
  FieldElement a = 200;
  FieldElement b = kPrioModulus - 100;

  // Test subtraction when first element is "smaller" in the field, with
  // underflow.
  EXPECT_EQ(SubMod(a, b), 300);

  // Test subtraction when first element is "larger" in the field.
  EXPECT_EQ(SubMod(b, a), kPrioModulus - 300);
}

TEST(FiniteFieldTest, AddMod) {
  // Test addition when the sum doesn't wrap around in the field.
  EXPECT_EQ(AddMod(100, 100), 200);

  // Test addition when the sum wraps in the field.
  EXPECT_EQ(AddMod(400, kPrioModulus - 300), 100);
}

TEST(FiniteFieldTest, MulMod) {
  // Test when the product doesn't wrap around in the field.
  EXPECT_EQ(MulMod(100, 5), 500);

  // Test when the product wraps in the field.
  EXPECT_EQ(MulMod(4, kPrioModulus - 300), kPrioModulus - 1200);
}

TEST(FiniteFieldTest, InvMod) { EXPECT_EQ(InvMod(1), 1); }

TEST(FiniteFieldTest, InvModIsMultiplicativeInverse) {
  FieldElement hundred_inverse = InvMod(100);

  EXPECT_EQ(MulMod(100, hundred_inverse), 1);
}

TEST(FiniteFieldTest, GenerateRandomFieldElementMinimumLargerMaximumError) {
  EXPECT_THAT(
      GenerateRandomFieldElement(2, 1),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("minimum is larger than the maximum")));
}

TEST(FiniteFieldTest, GenerateRandomFieldElementMinimumEqualMaximum) {
  for (FieldElement i :
       {FieldElement(0), FieldElement(1), kPrioModulus - 100}) {
    PRIO_ASSERT_OK_AND_ASSIGN(auto r, GenerateRandomFieldElement(i, i));
    EXPECT_EQ(r, i);
  }
}

TEST(FiniteFieldTest, GenerateRandomFieldElementIsRandom) {
  // This tests whether two sequences of random elements are distinct. This test
  // may fail with probability < 2^{-128}.
  bool equal = true;
  for (int i = 0; i < 10; i++) {
    PRIO_ASSERT_OK_AND_ASSIGN(auto r1,
                              GenerateRandomFieldElement(0, kPrioModulus - 1));
    PRIO_ASSERT_OK_AND_ASSIGN(auto r2,
                              GenerateRandomFieldElement(0, kPrioModulus - 1));
    equal &= (r1 == r2);
  }
  EXPECT_FALSE(equal);
}

TEST(FiniteFieldTest, GenerateRandomFieldElementIsWithinBounds) {
  for (FieldElement minimum :
       {FieldElement(0), FieldElement(kPrioModulus / 2), kPrioModulus - 100}) {
    for (FieldElement maximum :
         {FieldElement(1), FieldElement(kPrioModulus / 2), kPrioModulus - 1}) {
      if (minimum <= maximum) {
        PRIO_ASSERT_OK_AND_ASSIGN(auto r,
                                  GenerateRandomFieldElement(minimum, maximum));
        EXPECT_LE(r, maximum);
        EXPECT_GE(r, minimum);
      }
    }
  }
}

TEST(FiniteFieldTest, ConvertToFieldElements) {
  std::vector<FieldElement> elements;

  PRIO_ASSERT_OK_AND_ASSIGN(elements, ConvertToFieldElements(std::string({})));
  EXPECT_EQ(elements, std::vector<FieldElement>({}));

  PRIO_ASSERT_OK_AND_ASSIGN(
      elements, ConvertToFieldElements(std::string({0, 0, 0, 0, 0, 0, 0, 0})));
  EXPECT_EQ(elements, std::vector<FieldElement>({0, 0}));

  PRIO_ASSERT_OK_AND_ASSIGN(elements,
                            ConvertToFieldElements(std::string({1, 2, 3, 4})));
  EXPECT_EQ(elements, std::vector<FieldElement>({67305985 % kPrioModulus}));

  std::vector<uint8_t> mask({static_cast<uint8_t>(-1), static_cast<uint8_t>(-1),
                             static_cast<uint8_t>(-1),
                             static_cast<uint8_t>(-1)});

  PRIO_ASSERT_OK_AND_ASSIGN(
      elements, ConvertToFieldElements(std::string(mask.begin(), mask.end())));
  EXPECT_EQ(elements, std::vector<FieldElement>(
                          {static_cast<uint32_t>(-1) % kPrioModulus}));
}

TEST(FiniteFieldTest, ConvertToFieldElementsFailsOnMismatchedSize) {
  EXPECT_THAT(ConvertToFieldElements(std::string({0})),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("not a multiple")));
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
