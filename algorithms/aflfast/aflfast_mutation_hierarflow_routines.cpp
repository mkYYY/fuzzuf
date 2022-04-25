
#include "fuzzuf/algorithms/afl/afl_mutation_hierarflow_routines.hpp"
#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_state.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_testcase.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_havoc.hpp"

namespace fuzzuf::algorithm::afl::routine::mutation {

using AFLFastState = aflfast::AFLFastState;
using AFLFastTestcase = aflfast::AFLFastTestcase;

// explicit specialization
template<>
AFLMutCalleeRef<AFLFastState> HavocTemplate<AFLFastState>::operator()(
    AFLMutatorTemplate<AFLFastState>& mutator
) {
    // Declare the alias just to omit "this->" in this function.
    auto& state = this->state;

    s32 stage_max_multiplier;
    if (state.doing_det) stage_max_multiplier = option::GetHavocCyclesInit(state);
    else stage_max_multiplier = option::GetHavocCycles(state);

    using afl::dictionary::AFLDictData;

    if (this->DoHavoc(
                mutator,
                *state.mutop_optimizer,
                aflfast::havoc::AFLFastCustomCases,
                "more_havoc", "more_havoc",
                state.orig_perf, stage_max_multiplier,
                option::STAGE_HAVOC)) {
        this->SetResponseValue(true);
        return this->GoToParent();
    }

    return this->GoToDefaultNext();
}

}
