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

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "prio/constants.h"
#include "prio/finite_field.h"
#include "prio/status_macros.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {

namespace internal {

// Helper function to check whether x is not zero and a power-of-2.
static bool isNonZeroPowerOfTwo(size_t x) {
  return (x != 0) && ((x & (x - 1)) == 0);
}

// Recursive FFT algorithm.
static absl::Status FftRecurse(absl::Span<FieldElement> out,
                               const absl::Span<const FieldElement> roots,
                               const absl::Span<const FieldElement> ys,
                               absl::Span<FieldElement> tmp,
                               absl::Span<FieldElement> y_sub,
                               absl::Span<FieldElement> roots_sub) {
  auto sizes = {out.size(), roots.size(), ys.size(),
                tmp.size(), y_sub.size(), roots_sub.size()};
  if (ABSL_PREDICT_FALSE(std::min(sizes) != std::max(sizes))) {
    return absl::InvalidArgumentError(
        "The parameters of FftRecurse are not all of the same size.");
  }

  const size_t n = out.size();

  if (n == 1) {
    out[0] = ys[0];
    return absl::OkStatus();
  }

  // Recurse on the first half
  for (size_t i = 0; i < n / 2; i++) {
    y_sub[i] = AddMod(ys[i], ys[i + (n / 2)]);
    roots_sub[i] = roots[2 * i];
  }

  PRIO_RETURN_IF_ERROR(
      FftRecurse(tmp.subspan(0, n / 2), roots_sub.subspan(0, n / 2),
                 y_sub.subspan(0, n / 2), tmp.subspan(n / 2, n / 2),
                 y_sub.subspan(n / 2, n / 2), roots_sub.subspan(n / 2, n / 2)));
  for (size_t i = 0; i < n / 2; i++) {
    out[2 * i] = tmp[i];
  }

  // Recurse on the second half
  for (size_t i = 0; i < n / 2; i++) {
    y_sub[i] = SubMod(ys[i], ys[i + (n / 2)]);
    y_sub[i] = MulMod(y_sub[i], roots[i]);
  }

  PRIO_RETURN_IF_ERROR(
      FftRecurse(tmp.subspan(0, n / 2), roots_sub.subspan(0, n / 2),
                 y_sub.subspan(0, n / 2), tmp.subspan(n / 2, n / 2),
                 y_sub.subspan(n / 2, n / 2), roots_sub.subspan(n / 2, n / 2)));
  for (size_t i = 0; i < n / 2; i++) {
    out[2 * i + 1] = tmp[i];
  }

  return absl::OkStatus();
}

// Wrapper around the FFT and inverse NTT.
static absl::Status FftInterpolateRaw(
    absl::Span<FieldElement> out, const absl::Span<const FieldElement> ys,
    const absl::Span<const FieldElement> roots, bool invert) {
  auto sizes = {out.size(), roots.size(), ys.size()};
  if (ABSL_PREDICT_FALSE(std::min(sizes) != std::max(sizes))) {
    return absl::InvalidArgumentError(
        "The parameters of FftInterpolateRaw are not all of the same size.");
  }

  const size_t n = out.size();

  // Temporary variables that will be useful during computation of the Fft.
  std::vector<FieldElement> tmp(n);
  std::vector<FieldElement> y_sub(n);
  std::vector<FieldElement> roots_sub(n);

  PRIO_RETURN_IF_ERROR(FftRecurse(out, roots, ys, absl::MakeSpan(tmp),
                                  absl::MakeSpan(y_sub),
                                  absl::MakeSpan(roots_sub)));

  if (invert) {
    FieldElement n_inverse = InvMod(static_cast<FieldElement>(n));
    for (size_t i = 0; i < n; i++) {
      out[i] = MulMod(out[i], n_inverse);
    }
  }

  return absl::OkStatus();
}

// Helper function to compute roots of unity for the FFTs of size n_points and
// n_points/2.
absl::Status FftGetRoots(absl::Span<FieldElement> roots_out, bool invert) {
  const size_t n_points = roots_out.size();

  if (n_points < 2 || n_points > kPrioNumRoots) {
    return absl::InvalidArgumentError("The number of points is out of band.");
  }

  FieldElement gen = kPrioGenerator;
  if (invert) {
    gen = InvMod(gen);
  }

  roots_out[0] = 1;

  // Compute g' = g^step_size
  // Now, g' generates a subgroup of order n_points.
  const int step_size = kPrioNumRoots / n_points;
  gen = ExpMod(gen, step_size);

  roots_out[1] = gen;
  for (size_t i = 2; i < n_points; i++) {
    // Compute g^i for all i in {0,..., n-1}
    roots_out[i] = MulMod(gen, roots_out[i - 1]);
  }
  return absl::OkStatus();
}

}  // namespace internal

absl::StatusOr<std::unique_ptr<PolyParams>> PolyParams::Create(
    size_t number_points) {
  if (number_points >= kPrioModulus) {
    return absl::InvalidArgumentError(
        "The number of points in a polynomial is too large");
  }
  if (!internal::isNonZeroPowerOfTwo(number_points) || number_points < 2) {
    return absl::InvalidArgumentError(
        "The number of points in a polynomial should be a power of two, larger "
        "than 2.");
  }

  // Compute the roots and inverted roots.
  std::vector<FieldElement> roots(number_points);
  std::vector<FieldElement> roots_inverted(number_points);
  PRIO_RETURN_IF_ERROR(internal::FftGetRoots(absl::MakeSpan(roots), false));
  PRIO_RETURN_IF_ERROR(
      internal::FftGetRoots(absl::MakeSpan(roots_inverted), true));

  return absl::WrapUnique(
      new PolyParams(std::move(roots), std::move(roots_inverted)));
}

absl::StatusOr<Poly> Poly::InverseFft(
    const std::vector<FieldElement> &fft_coefficients,
    const PolyParams *params) {
  if (fft_coefficients.size() != params->Size()) {
    return absl::InvalidArgumentError(
        absl::StrCat("The number of coefficients, ", fft_coefficients.size(),
                     " does not match the expected size in the parameters, ",
                     params->Size()));
  }

  // Compute the inverse FFT.
  std::vector<FieldElement> new_coefficients = fft_coefficients;
  PRIO_RETURN_IF_ERROR(internal::FftInterpolateRaw(
      /*out=*/absl::MakeSpan(new_coefficients), fft_coefficients,
      absl::MakeConstSpan(params->roots_inverted_), /*invert=*/true));

  return Poly{std::move(new_coefficients), params};
}

absl::StatusOr<FieldElement> Poly::EvaluateIn(const FieldElement &a) {
  // Evaluate the polynomial in a.
  FieldElement result = 0;
  for (int i = static_cast<int>(coefficients_.size()) - 1; i >= 0; i--) {
    result = MulMod(result, a);
    result = AddMod(result, coefficients_[i]);
  }
  return result;
}

bool Poly::operator==(const Poly &p) const {
  if (coefficients_.size() != p.coefficients_.size()) {
    return false;
  }

  for (size_t i = 0; i < coefficients_.size(); i++) {
    if (coefficients_[i] != p.coefficients_[i]) {
      return false;
    }
  }

  return true;
}

absl::StatusOr<std::vector<FieldElement>> Poly::Fft(
    const PolyParams *export_params) const {
  std::vector<FieldElement> input_coefficients = coefficients_;
  input_coefficients.resize(export_params->Size());
  std::vector<FieldElement> fft_coefficients = coefficients_;
  fft_coefficients.resize(export_params->Size());

  PRIO_RETURN_IF_ERROR(internal::FftInterpolateRaw(
      absl::MakeSpan(fft_coefficients), input_coefficients,
      absl::MakeConstSpan(export_params->roots_), false));

  return fft_coefficients;
}

bool Poly::operator!=(const Poly &p) const { return !(*this == p); }

}  // namespace prio
}  // namespace private_statistics
