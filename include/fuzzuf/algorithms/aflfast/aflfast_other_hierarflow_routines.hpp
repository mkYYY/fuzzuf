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
#ifndef FUZZUF_INCLUDE_ALGORITHMS_AFLFAST_AFLFAST_OTHER_HIERARFLOW_ROUTINES_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_AFLFAST_AFLFAST_OTHER_HIERARFLOW_ROUTINES_HPP

#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_state.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_testcase.hpp"

namespace fuzzuf::algorithm::afl::routine::other {

using AFLFastState = aflfast::AFLFastState;
using AFLFastTestcase = aflfast::AFLFastTestcase;

#if 1
// explicit specialization
template <>
AFLMidCalleeRef<AFLFastState> ApplyDetMutsTemplate<AFLFastState>::operator()(
    std::shared_ptr<AFLFastTestcase> testcase);

// explicit specialization
template <>
AFLMidCalleeRef<AFLFastState> AbandonEntryTemplate<AFLFastState>::operator()(
    std::shared_ptr<AFLFastTestcase> testcase);
#endif

// explicit specialization
template <>
NullableRef<HierarFlowCallee<void(void)>>
SelectSeedTemplate<AFLFastState>::operator()(void);

void CreateAliasTable(AFLFastState &state);

double ComputeWeight(const AFLFastState &state, const AFLFastTestcase &testcase,
                     const double &avg_exec_us, const double &avg_bitmap_size,
                     const double &avg_top_size);

}  // namespace fuzzuf::algorithm::afl::routine::other
#endif
