#pragma once

#include "fuzzuf/optimizer/pso.hpp"
#include "fuzzuf/optimizer/store.hpp"
#include "fuzzuf/mutator/havoc_case.hpp"

namespace fuzzuf::optimizer {

namespace keys {

const StoreKey<u32> LastSpliceCycle { "last_splice_cycle" };
const StoreKey<u64> NewTestcases { "new_testcases" };
const StoreKey<std::array<std::array<u64, NUM_CASE>, 2>> HavocOperatorFinds { "havoc_operator_finds" }; // 0: pilot, 1: core


}

const size_t SwarmNum = 5;

class MOptParticle : public Particle<NUM_CASE> {
public:
    MOptParticle();
    ~MOptParticle();

    friend class MOptOptimizer;
private:
    std::array<double, NUM_CASE> fitness;
    std::array<double, NUM_CASE> best_fitness;
};


class MOptOptimizer : public PSO<NUM_CASE, SwarmNum> {

public:
    MOptOptimizer();
    ~MOptOptimizer();

    void Init();
    void UpdateLocalBest();
    void UpdateGlobalBest();
    void SetScore(size_t, double);

    void PSOUpdate(); // pso_updating

    bool opt_minimize = false;
private:
    std::array<MOptParticle, SwarmNum> swarm;
};

}