/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURE_AGGREGATION_SHELL_WRAPPER_STATUS_H_
#define SECURE_AGGREGATION_SHELL_WRAPPER_STATUS_H_

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "include/cxx.h"

// Forward-declare FfiStatus to avoid errors in the following generated header.
struct FfiStatus;
#include "shell_wrapper/status.rs.h"

namespace secure_aggregation {

FfiStatus MakeFfiStatus();
FfiStatus MakeFfiStatus(absl::Status status);
FfiStatus MakeFfiStatus(int code, std::string message);
absl::Status UnwrapFfiStatus(const FfiStatus& status);

}  // namespace secure_aggregation

extern "C" {

// To be called from Rust.
FfiStatus MakeFfiStatus(int code, rust::Slice<const uint8_t> message);

}  // extern "C"

#endif  // SECURE_AGGREGATION_SHELL_WRAPPER_STATUS_H_
