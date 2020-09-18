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

#include "prio/poly.h"

#include <cstddef>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "prio/constants.h"
#include "prio/finite_field.h"
#include "prio/testing/status_matchers.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {
namespace {

using ::testing::HasSubstr;
using testing::StatusIs;

const size_t kPolyDegree{4};

class PolyTest : public ::testing::Test {
 protected:
  void SetUp() override {
    params_n_ = PolyParams::Create(kPolyDegree).value();
    params_2n_ = PolyParams::Create(2 * kPolyDegree).value();
  }
  std::unique_ptr<PolyParams> params_n_, params_2n_;
};

// Test on the PolyParams
TEST_F(PolyTest, ParamsCheckSize) {
  EXPECT_THAT(
      PolyParams::Create(0),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("larger than 2")));
  EXPECT_THAT(
      PolyParams::Create(kPrioModulus + 1),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("too large")));
}

// Create polynomials
TEST_F(PolyTest, InverseNTT) {
  std::vector<FieldElement> input(kPolyDegree);
  PRIO_ASSERT_OK(Poly::InverseFft(input, params_n_.get()));
}

TEST_F(PolyTest, InverseNTTWithWrongSize) {
  std::vector<FieldElement> input(kPolyDegree + 1);
  EXPECT_THAT(Poly::InverseFft(input, params_n_.get()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match the expected size")));
}

TEST_F(PolyTest, InverseNTTWithWrongParams) {
  std::vector<FieldElement> input(kPolyDegree);
  EXPECT_THAT(Poly::InverseFft(input, params_2n_.get()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match the expected size")));
}

// Test that the Fft is working.
TEST_F(PolyTest, ExportImportFFT) {
  Poly p({1, 2, 3, 4}, params_n_.get());

  PRIO_ASSERT_OK_AND_ASSIGN(auto fft_coefficients, p.Fft(params_n_.get()));
  PRIO_ASSERT_OK_AND_ASSIGN(
      auto q, Poly::InverseFft(fft_coefficients, params_n_.get()));

  EXPECT_EQ(p, q);
}

TEST_F(PolyTest, ExportImportFFTDoubleSize) {
  std::vector<FieldElement> input = {1, 2, 3, 4};
  Poly p(input, params_n_.get());

  // Create a polynomial of degree 2*kPolyDegree where the top kPolyDegree
  // elements are 0.
  input.resize(kPolyDegree * 2);
  Poly expected(input, params_2n_.get());

  PRIO_ASSERT_OK_AND_ASSIGN(auto fft_coefficients, p.Fft(params_2n_.get()));
  PRIO_ASSERT_OK_AND_ASSIGN(
      auto q, Poly::InverseFft(fft_coefficients, params_2n_.get()));

  EXPECT_EQ(expected, q);
}

TEST_F(PolyTest, EvaluatesCorrectly) {
  Poly p({1, 2, 3, 4}, params_n_.get());

  PRIO_ASSERT_OK_AND_ASSIGN(auto eval0, p.EvaluateIn(0));
  EXPECT_EQ(eval0, 1);

  PRIO_ASSERT_OK_AND_ASSIGN(auto eval1, p.EvaluateIn(1));
  EXPECT_EQ(eval1, 1 + 2 + 3 + 4);

  PRIO_ASSERT_OK_AND_ASSIGN(auto eval2, p.EvaluateIn(2));
  EXPECT_EQ(eval2, 1 + 2 * (2) + 3 * (2 * 2) + 4 * (2 * 2 * 2));

  PRIO_ASSERT_OK_AND_ASSIGN(auto eval3, p.EvaluateIn(3));
  EXPECT_EQ(eval3, 1 + 2 * (3) + 3 * (3 * 3) + 4 * (3 * 3 * 3));
}

TEST_F(PolyTest, Multiply) {
  Poly p0({1, 2, 3, 4}, params_n_.get());
  Poly p1({3, 4, 5, 6}, params_n_.get());

  // Get the 2*n FFT coefficients of p0 and p1.
  PRIO_ASSERT_OK_AND_ASSIGN(std::vector<FieldElement> p0_fft_coefficients,
                            p0.Fft(params_2n_.get()));
  PRIO_ASSERT_OK_AND_ASSIGN(std::vector<FieldElement> p1_fft_coefficients,
                            p1.Fft(params_2n_.get()));

  // Multiply the FFT coefficients component-wise.
  EXPECT_EQ(p0_fft_coefficients.size(), p1_fft_coefficients.size());
  std::vector<FieldElement> p2_fft_coefficients;
  for (size_t i = 0; i < p0_fft_coefficients.size(); i++) {
    p2_fft_coefficients.push_back(
        MulMod(p0_fft_coefficients[i], p1_fft_coefficients[i]));
  }

  // Construct p2 from the FFT coefficients.
  PRIO_ASSERT_OK_AND_ASSIGN(
      auto p2, Poly::InverseFft(p2_fft_coefficients, params_2n_.get()));

  // Check that p2 = p0 * p1 by evaluating into 8 points.
  FieldElement a = 1;
  for (int i = 0; i < 8; i++) {
    PRIO_ASSERT_OK_AND_ASSIGN(auto p0i, p0.EvaluateIn(a));
    PRIO_ASSERT_OK_AND_ASSIGN(auto p1i, p1.EvaluateIn(a));
    PRIO_ASSERT_OK_AND_ASSIGN(auto p2i, p2.EvaluateIn(a));
    EXPECT_EQ(p2i, MulMod(p0i, p1i));
    a *= 2;
  }
}

}  // namespace
}  // namespace prio
}  // namespace private_statistics
