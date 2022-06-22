/*
 * fuzzuf
 * Copyright (C) 2021 Ricerca Security
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
#pragma once

#include <vector>
#include <array>
#include <memory>
#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/fuzzer/fuzzer.hpp"
#include "fuzzuf/algorithms/afl/afl_fuzzer.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_state.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_other_hierarflow_routines.hpp"

#include "fuzzuf/hierarflow/hierarflow_routine.hpp"
#include "fuzzuf/hierarflow/hierarflow_node.hpp"
#include "fuzzuf/hierarflow/hierarflow_intermediates.hpp"

namespace fuzzuf::algorithm::aflfast {

using AFLFastFuzzer = afl::AFLFuzzerTemplate<AFLFastState>;

} // namespace fuzzuf::algorithm::aflfast
