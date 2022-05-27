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

#ifndef FUZZUF_INCLUDE_ALGORITHM_AFLFAST_AFLFAST_STATE_HPP
#define FUZZUF_INCLUDE_ALGORITHM_AFLFAST_AFLFAST_STATE_HPP

#include <memory>

#include "fuzzuf/optimizer/optimizer.hpp"
#include "fuzzuf/algorithms/afl/afl_state.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_testcase.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_option.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_setting.hpp"

#define N_FUZZ_SIZE (1 << 21)

namespace fuzzuf::algorithm::aflfast {

struct AFLFastState : public afl::AFLStateTemplate<AFLFastTestcase> {
    explicit AFLFastState(
        std::shared_ptr<const AFLFastSetting> setting,
        std::shared_ptr<executor::AFLExecutorInterface> executor,
        std::unique_ptr<optimizer::Optimizer<u32>>&& mutop_optimizer
    );

    std::shared_ptr<AFLFastTestcase> AddToQueue(
        const std::string &fn,
        const u8 *buf,
        u32 len,
        bool passed_det
    );

    void UpdateBitmapScoreWithRawTrace(
        AFLFastTestcase &testcase,
        const u8 *trace_bits,
        u32 map_size
    );

    bool SaveIfInteresting(
        const u8 *buf,
        u32 len,
        InplaceMemoryFeedback &inp_feed,
        ExitStatusFeedback &exit_status
    );

    u32 DoCalcScore(AFLFastTestcase &testcase);

    void ShowStats(void);

    std::shared_ptr<const AFLFastSetting> setting;
    std::shared_ptr<u32[]> n_fuzz;
};

} // namespace fuzzuf::algorithm::aflfast

#endif
