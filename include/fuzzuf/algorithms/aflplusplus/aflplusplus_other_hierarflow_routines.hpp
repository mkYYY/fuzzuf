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
#ifndef FUZZUF_INCLUDE_ALGORITHMS_AFLPLUSPLUS_AFLPLUSPLUS_OTHER_HIERARFLOW_ROUTINES_HPP
#define FUZZUF_INCLUDE_ALGORITHMS_AFLPLUSPLUS_AFLPLUSPLUS_OTHER_HIERARFLOW_ROUTINES_HPP

#include "fuzzuf/algorithms/afl/afl_other_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_state.hpp"
#include "fuzzuf/algorithms/aflplusplus/aflplusplus_testcase.hpp"
#include "fuzzuf/utils/common.hpp"

namespace fuzzuf::algorithm::afl::routine::other {

using AFLplusplusState = aflplusplus::AFLplusplusState;
using AFLplusplusTestcase = aflplusplus::AFLplusplusTestcase;

// explicit specialization
template <>
AFLMidCalleeRef<AFLplusplusState>
ApplyDetMutsTemplate<AFLplusplusState>::operator()(
    std::shared_ptr<AFLplusplusTestcase> testcase);

// explicit specialization
template <>
AFLMidCalleeRef<AFLplusplusState>
AbandonEntryTemplate<AFLplusplusState>::operator()(
    std::shared_ptr<AFLplusplusTestcase> testcase);

// explicit specialization
template <>
utils::NullableRef<hierarflow::HierarFlowCallee<void(void)>>
SelectSeedTemplate<AFLplusplusState>::operator()(void);

void CreateAliasTable(AFLplusplusState& state);

void ComputeWeightVector(AFLplusplusState& state, std::vector<double>& vw);

double ComputeWeight(const AFLplusplusState& state,
                     const AFLplusplusTestcase& testcase,
                     const double& avg_exec_us, const double& avg_bitmap_size,
                     const double& avg_top_size);

}  // namespace fuzzuf::algorithm::afl::routine::other
#endif
