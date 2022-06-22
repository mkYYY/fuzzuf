#include "fuzzuf/algorithms/aflfast/aflfast_havoc.hpp"

#include "fuzzuf/utils/common.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"
#include "fuzzuf/mutator/mutator.hpp"
#include "fuzzuf/algorithms/afl/afl_mutator.hpp"
#include "fuzzuf/algorithms/afl/afl_option.hpp"
#include "fuzzuf/algorithms/afl/afl_dict_data.hpp"
#include "fuzzuf/algorithms/afl/count_classes.hpp"
#include "fuzzuf/algorithms/afl/afl_util.hpp"
#include "fuzzuf/utils/random.hpp"
#include "fuzzuf/algorithms/aflfast/aflfast_option.hpp"

namespace fuzzuf::algorithm::aflfast::havoc {

enum AFLFastExtraHavocCase : u32 {
    AFLPP_ADDBYTE = mutator::NUM_CASE,
    AFLPP_SUBBYTE,
    AFLPP_SWITCH_BYTES,
    AFLPP_NUM_CASE  // number of cases in AFL++ havoc
};

/**
 * @fn AFLFastGetCaseWeights
 * Returns the weights that represent the probabilities of each case being selected in Havoc.
 * @note Ridiculously, we need a constexpr function just in order to initialize static arrays 
 * with enum constants(i.e. to use a kind of designated initialization)
 */ 
static constexpr std::array<double, AFLPP_NUM_CASE> AFLFastGetCaseWeights(
    bool has_extras,
    bool has_a_extras
) {
    std::array<double, AFLPP_NUM_CASE> weights {};

    weights[mutator::FLIP1] = 4.0; // case 0 ... 3
    weights[mutator::INT8] = 4.0; // case 4 ... 7
    weights[mutator::INT16_LE] = 2.0; // case 8 ... 9
    weights[mutator::INT16_BE] = 2.0; // case 10 ... 11
    weights[mutator::INT32_LE] = 2.0; // case 12 ... 13
    weights[mutator::INT32_BE] = 2.0; // case 14 ... 15
    weights[mutator::SUB8] = 4.0; // case 16 ... 19
    weights[mutator::ADD8] = 4.0; // case 20 ... 23
    weights[mutator::SUB16_LE] = 2.0; // case 24 ... 25
    weights[mutator::SUB16_BE] = 2.0; // case 26 ... 27
    weights[mutator::ADD16_LE] = 2.0; // case 28 ... 29
    weights[mutator::ADD16_BE] = 2.0; // case 30 ... 31
    weights[mutator::SUB32_LE] = 2.0; // case 32 ... 33
    weights[mutator::SUB32_BE] = 2.0; // case 34 ... 35
    weights[mutator::ADD32_LE] = 2.0; // case 36 ... 37
    weights[mutator::ADD32_BE] = 2.0; // case 38 ... 39
    weights[mutator::XOR] = 4.0; // case 40 ... 43
    weights[mutator::CLONE_BYTES] = 3.0; // case 44 ... 46
    weights[mutator::INSERT_SAME_BYTE] = 1.0; // case 47
    weights[mutator::OVERWRITE_WITH_CHUNK]= 3.0; // case 48 ... 50
    weights[mutator::OVERWRITE_WITH_SAME_BYTE] = 1.0; // case 51
    weights[AFLPP_ADDBYTE] = 1.0; // case 52
    weights[AFLPP_SUBBYTE] = 1.0; // case 53
    weights[mutator::FLIP8] = 1.0; // case 54
    weights[AFLPP_SWITCH_BYTES] = 2.0; // case 55 ... 56
    weights[mutator::DELETE_BYTES] = 8.0; // case 57 ... 64

    if (has_extras && has_a_extras) {
        weights[mutator::INSERT_EXTRA]          = 1.0;
        weights[mutator::OVERWRITE_WITH_EXTRA]  = 1.0;
        weights[mutator::INSERT_AEXTRA]         = 1.0;
        weights[mutator::OVERWRITE_WITH_AEXTRA] = 1.0;
    } else if (has_extras) {
        weights[mutator::INSERT_EXTRA]          = 2.0;
        weights[mutator::OVERWRITE_WITH_EXTRA]  = 2.0;
    } else if (has_a_extras) {
        weights[mutator::INSERT_AEXTRA]         = 2.0;
        weights[mutator::OVERWRITE_WITH_AEXTRA] = 2.0;
    }

    return weights;
}

AFLFastHavocCaseDistrib::AFLFastHavocCaseDistrib() {}
AFLFastHavocCaseDistrib::~AFLFastHavocCaseDistrib() {}
u32 AFLFastHavocCaseDistrib::CalcValue() {
    const auto& extras = optimizer::Store::GetInstance().Get(optimizer::keys::Extras).value().get();
    const auto& a_extras = optimizer::Store::GetInstance().Get(optimizer::keys::AutoExtras).value().get();

    // Static part: the following part doesn't run after a fuzzing campaign starts.

    constexpr std::array<double, AFLPP_NUM_CASE> weight_set[2][2] = {
        { AFLFastGetCaseWeights(false, false), AFLFastGetCaseWeights(false, true) },
        { AFLFastGetCaseWeights(true,  false), AFLFastGetCaseWeights(true,  true) }
    };

    using fuzzuf::utils::random::WalkerDiscreteDistribution;
    static WalkerDiscreteDistribution<u32> dists[2][2] = {
      { WalkerDiscreteDistribution<u32>(weight_set[0][0].cbegin(),
                                        weight_set[0][0].cend()),
        WalkerDiscreteDistribution<u32>(weight_set[0][1].cbegin(),
                                        weight_set[0][1].cend()) },
      { WalkerDiscreteDistribution<u32>(weight_set[1][0].cbegin(),
                                        weight_set[1][0].cend()),
        WalkerDiscreteDistribution<u32>(weight_set[1][1].cbegin(),
                                        weight_set[1][1].cend()) }
    };

    // Dynamic part: the following part runs during a fuzzing campaign

    bool has_extras  = !extras.empty();
    bool has_aextras = !a_extras.empty();
    return static_cast<u32>(dists[has_extras][has_aextras]());
}

void AFLFastCustomCases(
    u32 case_idx,
    u8*& outbuf,
    u32& len,
    [[maybe_unused]] const std::vector<afl::dictionary::AFLDictData>& extras,
    [[maybe_unused]] const std::vector<afl::dictionary::AFLDictData>& a_extras
) {
    auto UR = [](u32 limit) {
        return afl::util::UR(limit, -1);
    };
    switch(case_idx) {
    case AFLPP_ADDBYTE:
        outbuf[UR(len)]++;
        break;

    case AFLPP_SUBBYTE:
        outbuf[UR(len)]--;
        break;

    case AFLPP_SWITCH_BYTES: {
        if (len < 4) { break; }

        u32 to_end, switch_to, switch_len, switch_from;
        switch_from = UR(len);
        do {
            switch_to = UR(len);
        } while (switch_from == switch_to);

        if (switch_from < switch_to) {
            switch_len = switch_to - switch_from;
            to_end = len - switch_to;
        } else {
            switch_len = switch_from - switch_to;
            to_end = len - switch_from;
        }

        switch_len = ChooseBlockLen(std::min(switch_len, to_end));

        std::unique_ptr<u8> new_buf(new u8[switch_len]);

        /* Backup */
        memcpy(new_buf.get(), outbuf + switch_from, switch_len);

        /* Switch 1 */
        memcpy(outbuf + switch_from, outbuf + switch_to, switch_len);

        /* Switch 2 */
        memcpy(outbuf + switch_to, new_buf.get(), switch_len);

        break;
    }

    default:
        break;
    }
}

// Temporarily copy-and-paste ChooseBlockLen() function, rather than modifying all function prototypes
// of CustomCases.
// Looking for a "lazier" way to achieve this...
u32 ChooseBlockLen(u32 limit)
{
    using Tag = aflfast::option::AFLFastTag;
    u32 min_value, max_value;
    u32 rlim = 3ULL; 

    // just an alias of afl::util::UR
    auto UR = [](u32 limit) {
        return afl::util::UR(limit, -1);
    };

    switch (UR(rlim)) {
    case 0:  min_value = 1;
             max_value = afl::option::GetHavocBlkSmall<Tag>();
             break;

    case 1:  min_value = afl::option::GetHavocBlkSmall<Tag>();
             max_value = afl::option::GetHavocBlkMedium<Tag>();
             break;
    default: 
        if (UR(10)) {
            min_value = afl::option::GetHavocBlkMedium<Tag>();
            max_value = afl::option::GetHavocBlkLarge<Tag>();
        } else {
            min_value = afl::option::GetHavocBlkLarge<Tag>();
            max_value = afl::option::GetHavocBlkXl<Tag>();
        }
    }

    if (min_value >= limit) min_value = 1;

    return min_value + UR(std::min(max_value, limit) - min_value + 1);
}

} // namespace fuzzuf::algorithm::aflfast::havoc
