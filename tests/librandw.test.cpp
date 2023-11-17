/*
 * The MIT License
 *
 * Copyright 2023 @olegasivakov.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * File:   librandw.test.cpp
 * Author: @olegasivakov
 *
 * Created on September 2, 2023, 9:57 PM
 */

#include <cstdlib>
#include <mutex>
#include <thread>

#include "./librandw.hpp"

#define ATTEMPTS 5

using namespace std;

/*
 * Tests
 */

void testGenerate() {
    std::map<int, int> rands;
    int k = 10;
    for (int i = 0; i < k; i++) {
        rands.insert({i, 0});
    }
    for (int i = 0; i < ATTEMPTS; i++) {
        //std::cout << std::endl << "ATTEMPT #" << i + 1 << std::endl;
        //std::cout << (int) (randw::get(randw::hash_mode::gost512) * 10) << std::endl;
        int r = (int) (randw::get(randw::hash_mode::gost512) * k);
        rands.at(r)++;
    }
    for (int i = 0; i < k; i++) {
        //if(1 < rands.at(i))
        std::cout << i << "\t" << rands.at(i) << std::endl;
    }
    //exit(0);
}

void testGenerate2() {
    int count = 10;
    for (int i = 0; i < ATTEMPTS; i++) {
        std::cout << std::endl << "ATTEMPT #" << i + 1 << std::endl;
        vector<double> result = randw::get_many(count);
        for (auto res : result)
            std::cout << std::fixed << std::setprecision(18) << res << std::endl;
    }
}

void testGenerate3() {
    int min = 0;
    int max = 100000000;
    for (int i = 0; i < ATTEMPTS; i++) {
        //std::cout << std::endl << "ATTEMPT #" << i + 1 << std::endl;
        map<int, int> results;
        for (int i = 0; i < 1000; i++) {
            int result = randw::get_range(min, max, randw::hash_mode::sha512);
            //std::cout << result << std::endl;
            if (results.find(result) == results.end())
                results.insert({result, 0});
            results.at(result)++;
        }

        int c = 0;
        for (auto pair : results) {
            // std::cout << pair.first << "\t" << pair.second << std::endl;
            if (1 < pair.second) c++;
        }

        if (0 < c) std::cout << "DOUBLES:\t" << c << std::endl;
        else std::cout << "OK" << std::endl;

    }
}

void testGenerate4() {
    vector<int> list = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    for (int i = 0; i < ATTEMPTS; i++) {
        std::cout << std::endl << "ATTEMPT #" << i + 1 << std::endl;
        vector<int> result = randw::get_shuffled_list(list);
        for (auto item : result)
            std::cout << item << std::endl;
    }
}

void testGenerate5() {
    for (int i = 0; i < ATTEMPTS; i++) {
        std::cout << std::endl << "ATTEMPT #" << i + 1 << std::endl;
        std::cout << randw::get_string(8) << std::endl;
    }
}

/**
 * Not implemented
 */
void testGenerate7() {
    for (int i = 0; i < ATTEMPTS; i++) {
        std::cout << std::endl << "ATTEMPT #" << i + 1 << std::endl;
        std::cout << "SHA HASHING 512" << std::endl;
        std::cout << randw::bignum::dec() << std::endl;
        std::cout << randw::bignum::hex() << std::endl;
        std::cout << "SHA HASHING 256" << std::endl;
        std::cout << randw::bignum::dec(randw::hash_mode::sha256) << std::endl;
        std::cout << randw::uint256::get(randw::hash_mode::sha256) << std::endl;
        std::cout << "GOST HASHING 512" << std::endl;
        std::cout << randw::bignum::dec(randw::hash_mode::gost512) << std::endl;
        std::cout << randw::bignum::hex(randw::hash_mode::gost512) << std::endl;
        std::cout << "GOST HASHING 256" << std::endl;
        std::cout << randw::bignum::dec(randw::hash_mode::gost256) << std::endl;
        std::cout << randw::uint256::get(randw::hash_mode::gost256) << std::endl;
    }
}

void testGenerate8() {
    std::mutex m;
    int count = 10000000;
    map<double, uint64_t> list;
    static auto run = [ & ](int k) {
        for (int i = 0; i < count; i++) {
            //auto r = randw::get(randw::hash_mode::gost512);
            auto r = randw::get(randw::hash_mode::sha256);

            m.lock();

            if (list.find(r) == list.end()) list.insert({r, 0});
            else list.at(r)++;

            if (0 == i % 1000) {
                std::cout << k << "\t" << std::fixed << std::setprecision(54) << r << "\t" << list.size() << "\t";

                int c = 0;
                for (auto pair : list) {
                    if (0 < pair.second) c++;
                }
                if (0 < c) std::cout << "DOUBLES:\t" << c << std::endl;
                else std::cout << "OK" << std::endl;
            }
            m.unlock();
        }
    };

    std::thread(run, 0).join();

    int c = 0;
    for (auto pair : list) {
        if (0 < pair.second) c++;
    }
    if (0 < c) std::cout << "DOUBLES:\t" << c << std::endl;
    else std::cout << "OK" << std::endl;
}

int main(int argc, char** argv) {

    std::cout << "STARTING tests" << std::endl;
    std::cout << "STARTED" << std::endl;

    std::cout << std::endl << "- - - - -" << std::endl << "TEST STARTED testGenerate()" << std::endl;
    testGenerate();
    std::cout << std::endl << "TEST FINISHED testGenerate()" << std::endl;

    std::cout << std::endl << "- - - - -" << std::endl << "TEST STARTED testGenerate2()" << std::endl;
    testGenerate2();
    std::cout << std::endl << "TEST FINISHED testGenerate2()" << std::endl;

    std::cout << std::endl << "- - - - -" << std::endl << "TEST STARTED testGenerate3()" << std::endl;
    testGenerate3();
    std::cout << std::endl << "TEST FINISHED testGenerate3()" << std::endl;

    std::cout << std::endl << "- - - - -" << std::endl << "TEST STARTED testGenerate4()" << std::endl;
    testGenerate4();
    std::cout << std::endl << "TEST FINISHED testGenerate4()" << std::endl;

    std::cout << std::endl << "- - - - -" << std::endl << "TEST STARTED testGenerate5()" << std::endl;
    testGenerate5();
    std::cout << std::endl << "TEST FINISHED testGenerate5()" << std::endl;

    std::cout << std::endl << "- - - - -" << std::endl << "TEST STARTED testGenerate7()" << std::endl;
    testGenerate7();
    std::cout << std::endl << "TEST FINISHED testGenerate7()" << std::endl;

    std::cout << std::endl << "- - - - -" << std::endl << "TEST STARTED testGenerate8()" << std::endl;
    testGenerate8();
    std::cout << std::endl << "TEST FINISHED testGenerate8()" << std::endl;

    std::cout << std::endl << "FINISHED" << std::endl;
    return (EXIT_SUCCESS);
}
