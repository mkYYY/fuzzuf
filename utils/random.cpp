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
/**
 * @file random.cpp
 * @author Ricerca Security <fuzzuf-dev@ricsec.co.jp>
 */
#include <random>
namespace fuzzuf::utils::random {
namespace {
  std::random_device rd;
  std::default_random_engine eng(rd());
}
  int RandInt(int lower, int upper) {
    std::uniform_int_distribution<int> distr(lower, upper);
    return distr(eng);
  }
}
