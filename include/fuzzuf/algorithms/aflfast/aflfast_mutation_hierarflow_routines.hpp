/*
 * fuzzuf
 * Copyright (C) 2022 Ricerca Security
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

#ifndef FUZZUF_INCLUDE_ALGORITHM_AFLFAST_AFLFAST_MUTATION_HIERARFLOW_ROUTINES_HPP
#define FUZZUF_INCLUDE_ALGORITHM_AFLFAST_AFLFAST_MUTATION_HIERARFLOW_ROUTINES_HPP

#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_state.hpp"

namespace fuzzuf::algorithm::afl::routine::mutation {

using AFLFastState = aflfast::AFLFastState;

// explicit specialization
template<>
AFLMutCalleeRef<AFLFastState> HavocTemplate<AFLFastState>::operator()(
    AFLMutatorTemplate<AFLFastState>& mutator
);

} // namespace fuzzuf::algorithm::afl::routine::mutation

#endif