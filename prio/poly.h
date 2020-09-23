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

#ifndef LIBPRIO_CC_PRIO_POLY_H_
#define LIBPRIO_CC_PRIO_POLY_H_

#include <memory>
#include <ostream>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/types/span.h"
#include "prio/types.h"

namespace private_statistics {
namespace prio {

// Forward declaration of Poly.
class Poly;

// Parameters that will be useful to compute the Fast Fourier Transform.
// go/thread-safe
class PolyParams {
 public:
  // Factory function to create the polynomial parameters. It takes as input the
  // number of points. It returns an error if the number of points is not a
  // power of two.
  static absl::StatusOr<std::unique_ptr<PolyParams>> Create(
      size_t number_points);

  // Returns the size of the FFT representation.
  const size_t Size() const { return roots_.size(); }

 private:
  friend class Poly;

  PolyParams(std::vector<FieldElement> roots,
             std::vector<FieldElement> roots_inverted)
      : roots_(std::move(roots)), roots_inverted_(std::move(roots_inverted)) {}

  const std::vector<FieldElement> roots_;
  const std::vector<FieldElement> roots_inverted_;
};

// Class that holds a polynomial of degree N, in "plain" coefficient
// representation.
class Poly {
 public:
  // Construct a polynomial from plain coefficients. Note that the coefficients
  // at indices larger than params.Size() will be ignored. If fewer coefficients
  // are provided, they will be padded with 0s in the higher order coefficients
  Poly(std::vector<FieldElement> plain_coefficients, const PolyParams* params)
      : coefficients_(std::move(plain_coefficients)), params_(params) {
    // Resize the coefficients to match the number of elements in the parameters
    coefficients_.resize(params_->Size());
  }

  // Construct a polynomial by specifying its FFT coefficients. If the number of
  // coefficients differ from the size in the parameters, an
  // InvalidArgumentError is returned.
  static absl::StatusOr<Poly> InverseFft(
      const std::vector<FieldElement>& fft_coefficients,
      const PolyParams* params);

  // Evaluate the polynomial at the point `a`.
  absl::StatusOr<FieldElement> EvaluateIn(const FieldElement& a);

  // Operators
  bool operator==(const Poly& p) const;
  bool operator!=(const Poly& p) const;

  // Get the FFT coefficients of the polynomial, under the specified parameters.
  // The specified parameters enable to compute a FFT into a higher or lower
  // dimension, in which casse, the coefficients will be resized (and
  // potentially appended with 0s) to the dimension in the specified parameters.
  absl::StatusOr<std::vector<FieldElement>> Fft(
      const PolyParams* export_params) const;

 private:
  std::vector<FieldElement> coefficients_;  // plain coefficient representation.
  const PolyParams* params_;
};

}  // namespace prio
}  // namespace private_statistics

#endif  // LIBPRIO_CC_PRIO_POLY_H_
