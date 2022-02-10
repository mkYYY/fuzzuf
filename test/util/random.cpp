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
#define BOOST_TEST_MODULE nautilus.dice
#define BOOST_TEST_DYN_LINK

#include <algorithm>
#include <boost/test/unit_test.hpp>
#include <future>
#include <numeric>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>
#include "fuzzuf/utils/random.hpp"


using namespace fuzzuf::utils::random;

BOOST_AUTO_TEST_CASE(TestRandomAndChoose) {
  std::vector<int> v1 = {10, 11, 12, 13, 14, 15, 16, 17};
  const int v2[] = {10, 11, 12, 13, 14, 15, 16, 17};
  std::vector<double> v3 = {3.14};
  std::vector<int> v4 = {};

  for (size_t i = 0; i < 10000; i++) {
    int r1 = Random<int>(0, 10);
    char r2 = Random<char>(-100, 100);
    int r3 = Choose<int>(v1);
    int r4 = Choose<int>(v2, 8);
    double r5 = Choose<double>(v3);
    BOOST_CHECK(0 <= r1 && r1 <= 10);
    BOOST_CHECK(-100 <= r2 && r2 <= 100);
    BOOST_CHECK(10 <= r3 && r3 <= 17);
    BOOST_CHECK(10 <= r4 && r4 <= 17);
    BOOST_CHECK(r5 == 3.14);
  }

  bool exception_thrown = false;
  try {
    int r6 = Choose<int>(v4);
    std::cerr << "Something chosen from an empty vector: " << r6 << std::endl;
  } catch(const std::out_of_range&) {
    exception_thrown = true;
  }
  BOOST_CHECK(exception_thrown);
}


BOOST_AUTO_TEST_CASE(TestWalkerDiscreteDistributionSimple) {
  /* Get random probabilities */
  size_t len = Random<size_t>(3, 9);
  std::vector<double> base;
  for (size_t i = 0; i < len; i++) {
    base.push_back(Random<double>(0.0, 1.0));
  }

  /* Normalize */
  double sum = std::accumulate(base.begin(), base.end(), 0.0);
  for (double& v: base) {
    v /= sum;
  }

  WalkerDiscreteDistribution<double> s(base);
  std::vector<size_t> res(len);

  size_t iter = 1000000; // large enough
  for (size_t i = 0; i < iter; i++) {
    res[s()]++;
  }

  std::vector<double> res_p;
  for (size_t f: res) {
    res_p.push_back(static_cast<double>(f) / static_cast<double>(iter));
  }

  for (size_t i = 0; i < len; i++) {
    BOOST_CHECK(base[i] * 0.95 < res_p[i] && base[i] * 1.05 > res_p[i]);
  }
}

BOOST_AUTO_TEST_CASE(TestWalkerDiscreteDistributionBiased) {
  size_t iter = 1000000;
  bool exception_thrown;

  /* 1. Test biased weights */
  std::vector<double> w1{10000.0, 0.0, 0.0, 100.0, 100.0};
  double sum = std::accumulate(w1.begin(), w1.end(), 0);
  WalkerDiscreteDistribution<double> s1(w1);
  std::vector<size_t> res1(w1.size());
  for (size_t i = 0; i < iter; i++) {
    res1[s1()]++;
  }
  for (size_t i = 0; i < w1.size(); i++) {
    double pa = w1[i] / sum;
    double ps = static_cast<double>(res1[i]) / static_cast<double>(iter);
    BOOST_CHECK(pa*0.9 <= ps && ps <= pa*1.1);
  }

  /* 2. Test invalid weights */
  // negative weight
  std::vector<int> w2{314, -1592, 0, 1};
  exception_thrown = false;
  try {
    WalkerDiscreteDistribution<int> s2(w2);
  } catch (std::range_error&) {
    exception_thrown = true;
  }
  BOOST_CHECK(exception_thrown);
  // NaN weight
  std::vector<float> w3{3.14, 15.92, std::nanf("")};
  exception_thrown = false;
  try {
    WalkerDiscreteDistribution<float> s3(w3);
  } catch (std::range_error&) {
    exception_thrown = true;
  }
  BOOST_CHECK(exception_thrown);

  /* 3. Test zero-ed weights */
  std::vector<char> w4{0, 0, 0};
  WalkerDiscreteDistribution<char> s4(w4);
  std::vector<size_t> res4(w4.size());
  for (size_t i = 0; i < iter; i++) {
    res4[s4()]++;
  }
  for (size_t i = 0; i < w4.size(); i++) {
    constexpr double pa = 1.0 / 3.0;
    double ps = static_cast<double>(res4[i]) / static_cast<double>(iter);
    BOOST_CHECK(pa*0.9 <= ps && ps <= pa*1.1);
  }

  /* 4. Test infinity sum */
  std::vector<double> w5{
    std::numeric_limits<double>::max(),
    std::numeric_limits<double>::max()
  };
  exception_thrown = false;
  try {
    WalkerDiscreteDistribution<double> s5(w5);
  } catch (std::range_error&) {
    exception_thrown = true;
  }
  BOOST_CHECK(exception_thrown);

  /* Test small number of big weights */
  std::vector<double> w6{1.0, std::numeric_limits<double>::max()};
  WalkerDiscreteDistribution<double> s6(w6);
  for (size_t i = 0; i < iter; i++) {
    BOOST_CHECK(s6() == 1);
  }
}
