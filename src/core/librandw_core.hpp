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
 * File:   librandw.core.hpp
 * Author: @olegasivakov
 *
 * Created on September 2, 2023, 8:53 PM
 */

#ifndef LIBRANDW_CORE_HPP
#define LIBRANDW_CORE_HPP

/**
 * MACROS
 */

/**
 * SECTION 1: VERSION DATA.  These will change for each release
 */

/*
 * These macros express version number MAJOR.MINOR.PATCH exactly
 */
#define LIBRANDW_VERSION_MAJOR  0
#define LIBRANDW_VERSION_MINOR  1
#define LIBRANDW_VERSION_PATCH  5

/**
 * SECTION 2: IV initial value
 */

// 1st value for IV. Change if need
#define SET_IV "LIBRANDW"

/**
 * SECTION 3: Macros for tests
 */

// Uncomment if need for tests
//#define ALLOW_STAT

/**
 * LIBRANDW
 */

#include <algorithm>
#include <bitset>
#include <chrono>
#include <complex>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <map>
#include <random>
#include <sstream>
#include <stdfix.h>
#include <stdint.h>
#include <string>
#include <time.h>
#include <unistd.h>
#include <vector>

#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <openssl/bn.h>

#include "../vars/crypto/vars_crypto.hpp"
#include "../vendor/uint256/uint256_t.h"

typedef uint8_t Vint8[BLOCK_SIZE];

using std::map;
using std::string;
using std::vector;

#ifdef ALLOW_STAT

struct stat_t {
    int iters = 0;
    uint64_t end = 0, start = 0;
};
stat_t STAT;
#endif

template< typename pair_t >
struct second_t {

    typename pair_t::second_type operator()(const pair_t& p) const {
        return p.second;
    }
};

template< typename map_t >
second_t< typename map_t::value_type > second(const map_t& m) {
    return second_t< typename map_t::value_type > ();
}

namespace randw {

    namespace hash_mode {

        enum {
            gost256 = 0,
            gost512,
            // @TODO
            //hmac256,
            //hmac512,
            sha256,
            sha512,
        };
    };

    namespace lib {

        class gost {
        private:

            typedef struct hContext {
                Vint8 buffer;
                Vint8 hash;
                Vint8 h;
                Vint8 N;
                Vint8 Sigma;
                Vint8 v_0;
                Vint8 v_512;
                size_t buf_size;
                int hash_size;
            } ThContext;

        public:

            static auto hash(string const &str, int hashSize = 512)->BIGNUM* {
                ThContext *CTX = (ThContext*) (malloc(sizeof (ThContext)));
                uint8_t *buffer;

                {
                    int strSize = str.size();
                    buffer = (uint8_t *) malloc(strSize);
                    memcpy(buffer, str.c_str(), strSize);
                    gost::_init(CTX, hashSize);
                    gost::_update(CTX, buffer, strSize);
                    gost::_final(CTX);
                }

                string data;
                switch (hashSize) {
                    case 256:
                    {
                        for (auto i = 32; i < 64; i++)
                            data += CTX->hash[i];
                        break;
                    }
                    case 512:
                    {
                        for (auto i = 0; i < 64; i++)
                            data += CTX->hash[i];
                        break;
                    }
                }
                free(buffer);
                free(CTX);
                return BN_bin2bn((unsigned char*) data.c_str(), data.size(), NULL);
            };

        private:

            static auto _x(const uint8_t *a, const uint8_t *b, uint8_t *c)->void {
                for (int i = 0; i < 64; i++) c[i] = a[i]^b[i];
            };
            static auto _add_512(const uint8_t *a, const uint8_t *b, uint8_t *c)->void {
                unsigned int tmp = 0;
                for (int i = 0; i < 64; i++) {
                    tmp = a[i] + b[i] + (tmp >> 8);
                    c[i] = tmp & 0xff;
                }
            };
            static auto _p(uint8_t *state)->void {
                Vint8 tmp;
                for (int i = 63; i >= 0; i--)
                    tmp[i] = state[randw::lib::vars::crypto::Tau[i]];
                memcpy(state, tmp, BLOCK_SIZE);
            };
            static auto _s(uint8_t *state)->void {
                Vint8 tmp;
                for (int i = 63; i >= 0; i--)
                    tmp[i] = randw::lib::vars::crypto::Pi[state[i]];
                memcpy(state, tmp, BLOCK_SIZE);
            };
            static auto _l(uint8_t *state)->void {
                uint64_t out[8];
                {
                    uint64_t* in = (uint64_t*) state;
                    memset(out, 0x00, BLOCK_SIZE);
                    for (int i = 7; i >= 0; i--) {
                        for (int j = 63; j >= 0; j--)
                            if ((in[i] >> j) & 1)
                                out[i] ^= randw::lib::vars::crypto::A[63 - j];
                    }
                }
                memcpy(state, out, 64);
            };
            static auto _key(uint8_t *K, int i)->void {
                _x(K, randw::lib::vars::crypto::C[i], K);
                _s(K);
                _p(K);
                _l(K);
            };
            static auto _e(uint8_t *K, const uint8_t *m, uint8_t *state)->void {
                memcpy(K, K, BLOCK_SIZE);
                _x(m, K, state);
                for (int i = 0; i < 12; i++) {
                    _s(state);
                    _p(state);
                    _l(state);
                    _key(K, i);
                    _x(state, K, state);
                }
            };
            static auto _g(uint8_t *h, uint8_t *N, const uint8_t *m)->void {
                Vint8 K, tmp;
                _x(N, h, K);
                _s(K);
                _p(K);
                _l(K);
                _e(K, m, tmp);
                _x(tmp, h, tmp);
                _x(tmp, m, h);
            };
            static auto _padding(ThContext *CTX)->void {
                if (CTX->buf_size < BLOCK_SIZE) {
                    Vint8 tmp;
                    memset(tmp, 0x00, BLOCK_SIZE);
                    memcpy(tmp, CTX->buffer, CTX->buf_size);
                    tmp[CTX->buf_size] = 0x01;
                    memcpy(CTX->buffer, tmp, BLOCK_SIZE);
                }
            };
            static auto hStage_2(ThContext *CTX, const uint8_t *data)->void {
                _g(CTX->h, CTX->N, data);
                _add_512(CTX->N, CTX->v_512, CTX->N);
                _add_512(CTX->Sigma, data, CTX->Sigma);
            };
            static auto _stage_3(ThContext *CTX)->void {
                {
                    Vint8 tmp;
                    memset(tmp, 0x00, BLOCK_SIZE);
                    tmp[1] = ((CTX->buf_size * 8) >> 8) & 0xff;
                    tmp[0] = (CTX->buf_size * 8) & 0xff;

                    _padding(CTX);
                    _g(CTX->h, CTX->N, (const uint8_t*) &(CTX->buffer));
                    _add_512(CTX->N, tmp, CTX->N);
                    _add_512(CTX->Sigma, CTX->buffer, CTX->Sigma);
                }

                _g(CTX->h, CTX->v_0, (const uint8_t*) &(CTX->N));
                _g(CTX->h, CTX->v_0, (const uint8_t*) &(CTX->Sigma));

                memcpy(CTX->hash, CTX->h, BLOCK_SIZE);
            };
            static auto _init(ThContext *CTX, uint16_t hash_size)->void {
                memset(CTX, 0x00, sizeof (ThContext));
                if (hash_size == 256)
                    memset(CTX->h, 0x01, BLOCK_SIZE);
                else
                    memset(CTX->h, 0x00, BLOCK_SIZE);
                CTX->hash_size = hash_size;
                CTX->v_512[1] = 0x02;
            };
            static auto _update(ThContext *CTX, const uint8_t *data, size_t len)->void {
                while ((len > 63) && (CTX->buf_size) == 0) {
                    gost::hStage_2(CTX, data);
                    data += 64;
                    len -= 64;
                }
                size_t size;
                while (len) {
                    size = 64 - CTX->buf_size;
                    if (size > len)
                        size = len;
                    memcpy(&CTX->buffer[CTX->buf_size], data, size);
                    CTX->buf_size += size;
                    len -= size;
                    data += size;
                    if (CTX->buf_size == 64) {
                        gost::hStage_2(CTX, CTX->buffer);
                        CTX->buf_size = 0;
                    }
                }
            };
            static auto _final(ThContext *CTX)->void {
                _stage_3(CTX);
                CTX->buf_size = 0;
            };
        };

        class hash {
        public:

            static auto get(string const& data, int hash_mode = randw::hash_mode::sha512)->double {
                switch (hash_mode) {
                    case randw::hash_mode::gost256:
                        return to_double(BN_bn2dec(gost::hash(data, 256)), 64);
                    case randw::hash_mode::gost512:
                        return to_double(BN_bn2dec(gost::hash(data, 512)), 128);

                        // @TODO
                        //case randw::hash_mode::hmac256:
                        //case randw::hash_mode::hmac512:
                        //    return 0;

                    case randw::hash_mode::sha256:
                        return to_double(to_bn_dec(sha256(data)), 64);
                    case randw::hash_mode::sha512:
                        return to_double(to_bn_dec(sha512(data)), 128);
                }
                return 0.0;
            };
            static auto bn(string const& data, int hash_mode = randw::hash_mode::sha512)->BIGNUM* {
                switch (hash_mode) {
                    case randw::hash_mode::gost256:
                        return gost::hash(data, 256);
                    case randw::hash_mode::gost512:
                        return gost::hash(data, 512);

                        // @TODO
                        //case randw::hash_mode::hmac256:
                        //case randw::hash_mode::hmac512:
                        //    return 0;

                    case randw::hash_mode::sha256:
                    {
                        auto data_ = sha256(data);
                        return BN_bin2bn((unsigned char*) data_.c_str(), data_.size(), NULL);
                    }
                    case randw::hash_mode::sha512:
                    {
                        auto data_ = sha512(data);
                        return BN_bin2bn((unsigned char*) data_.c_str(), data_.size(), NULL);
                    }
                }
                return NULL;
            };
            static auto hmac(string &key, string& message, int size = 256)->string {
                return "";
            };

        public:

            static auto to_bn_dec(string const& data)->char* {
                return BN_bn2dec(BN_bin2bn((unsigned char*) data.c_str(), data.size(), NULL));
            };
            static auto to_double(char *c, int power)->double {
                return (double) std::stod(c) / pow(16, power);
            };

        private:

            static auto sha256(string const& data)->string {

                unsigned char hash[SHA256_DIGEST_LENGTH];
#if(OPENSSL_VERSION_MAJOR < 3)
                SHA256_CTX CTX;
                SHA256_Init(&CTX);
                SHA256_Update(&CTX, data.c_str(), data.size());
                SHA256_Final(hash, &CTX);
                std::array<uint8_t, 32> tmp;
                for (auto i = 0; i < SHA256_DIGEST_LENGTH; i++) tmp[i] = hash[i];
                return string(std::begin(tmp), std::end(tmp));
#else
                SHA256(
                        reinterpret_cast<unsigned char const*> (data.c_str()),
                        static_cast<int> (data.size()),
                        hash
                        );
#endif
                return string{reinterpret_cast<char const*> (hash), SHA256_DIGEST_LENGTH};

            };
            static auto sha512(string const& data)->string {

                unsigned char hash[SHA512_DIGEST_LENGTH];
#if(OPENSSL_VERSION_MAJOR < 3)
                SHA512_CTX CTX;
                SHA512_Init(&CTX);
                SHA512_Update(&CTX, data.c_str(), data.size());
                SHA512_Final(hash, &CTX);

                // @TODO
                std::array<uint8_t, 64> tmp;
                for (auto i = 0; i < SHA512_DIGEST_LENGTH; i++) tmp[i] = hash[i];
                return string(std::begin(tmp), std::end(tmp));
#else
                SHA512(
                        reinterpret_cast<unsigned char const*> (data.c_str()),
                        static_cast<int> (data.size()),
                        hash
                        );
#endif
                return string{reinterpret_cast<char const*> (hash), SHA512_DIGEST_LENGTH};
            };

        private:

            static auto hmac256(string const& key_, string const& msg)->string {

                unsigned char hash[SHA256_DIGEST_LENGTH];
#if(OPENSSL_VERSION_MAJOR < 3)
                string key(key_.c_str());
                HMAC_CTX *CTX = HMAC_CTX_new();
                HMAC_Init_ex(CTX, (unsigned char *) key.c_str(), key.length(), EVP_sha256(), NULL);
                HMAC_Update(CTX, (unsigned char *) msg.c_str(), msg.length());
                unsigned int len = SHA256_DIGEST_LENGTH;
                HMAC_Final(CTX, hash, &len);
                HMAC_CTX_free(CTX);
#else
                unsigned int len;
                HMAC(
                        EVP_sha256(),
                        key_.c_str(),
                        static_cast<int> (key_.size()),
                        reinterpret_cast<unsigned char const*> (msg.c_str()),
                        static_cast<int> (msg.size()),
                        hash,
                        &len
                        );
#endif
                return string{reinterpret_cast<char const*> (hash), len};

            };
            static auto hmac512(string const& key_, string const& msg)->string {

                unsigned char hash[SHA512_DIGEST_LENGTH];
#if(OPENSSL_VERSION_MAJOR < 3)
                string key(key_.c_str());
                HMAC_CTX *CTX = HMAC_CTX_new();
                HMAC_Init_ex(CTX, (unsigned char *) key.c_str(), key.length(), EVP_sha512(), NULL);
                HMAC_Update(CTX, (unsigned char *) msg.c_str(), msg.length());
                unsigned int len = SHA512_DIGEST_LENGTH;
                HMAC_Final(CTX, hash, &len);
                HMAC_CTX_free(CTX);
#else
                unsigned int len;
                HMAC(
                        EVP_sha512(),
                        key_.c_str(),
                        static_cast<int> (key_.size()),
                        reinterpret_cast<unsigned char const*> (msg.data()),
                        static_cast<int> (msg.size()),
                        hash,
                        &len
                        );
#endif
                return string{reinterpret_cast<char const*> (hash), len};

            };

        };

        class generator {
        private:

            auto make_str(uint64_t &counter, double &random)->string {
                std::stringstream ss;
                ss
                        << std::fixed << std::setprecision(54)
                        << random << ";"
                        << counter++;
                for (auto var :{
                        ts(),
                        ts(counter)
                    }) ss << ";" << var;
                for (auto prime : PRIMES)
                    ss << ";" << ts(counter) % prime;

#ifdef ALLOW_STAT
                //std::cout << ss.str() << std::endl;
#endif

                return ss.str();
            };
            auto make_str(uint64_t &counter, BIGNUM *random)->string {
                std::stringstream ss;
                ss
                        << BN_bn2hex(random) << ";"
                        << counter++
                        ;
                for (auto var :{
                        ts(),
                        ts(counter)
                    }) ss << ";" << var;
                for (auto prime : PRIMES)
                    ss << ";" << ts(counter) % prime;

#ifdef ALLOW_STAT
                //std::cout << ss.str() << std::endl;
#endif

                return ss.str();
            };

        public:

            auto run(uint64_t &counter, double &random, int hash_mode = randw::hash_mode::sha512)->generator* {
                if (UINT16_MAX < counter) counter = 0;

#ifdef ALLOW_STAT
                STAT.iters++;
                STAT.start = ts();
#endif

                uint64_t start = ts(counter) + counter++;
                BIGNUM *tmp = randw::lib::hash::bn(
                        std::to_string(start),
                        hash_mode);
                for (string initial : IV)
                    tmp = randw::lib::hash::bn(string(BN_bn2hex(tmp))
                        .append(";")
                        .append(initial),
                        hash_mode);
                for (auto i = 0; i < len(counter, start); i++) {
#ifdef ALLOW_STAT
                    STAT.iters++;
#endif
                    tmp = randw::lib::hash::bn(
                            make_str(counter, tmp),
                            hash_mode);
                }
                random = hash::to_double(BN_bn2dec(tmp), (
                        hash_mode == randw::hash_mode::gost256 ||
                        hash_mode == randw::hash_mode::sha256) ?
                        64 : 128);

#ifdef ALLOW_STAT
                STAT.end = ts();
                std::cout
                        << "i:\t" << STAT.iters << std::endl
                        << "s:\t" << STAT.start << std::endl
                        << "e:\t" << STAT.end << std::endl
                        << "d:\t" << STAT.end - STAT.start << std::endl
                        << "c:\t" << counter << std::endl;
                ;
                //exit(0);
#endif

                return this;
            };

            auto bn(uint64_t &counter, int hash_mode = randw::hash_mode::sha512)->BIGNUM* {
                if (UINT16_MAX < counter) counter = 0;

                BIGNUM *random;
                uint64_t start = ts(counter) + counter++;
                random = randw::lib::hash::bn(
                        std::to_string(start),
                        hash_mode);
                for (string initial : IV)
                    random = randw::lib::hash::bn(string(BN_bn2hex(random))
                        .append(";")
                        .append(initial),
                        hash_mode);
                for (auto i = 0; i < len(counter, start); i++)
                    random = randw::lib::hash::bn(
                        make_str(counter, random),
                        hash_mode);

                return random;
            };

        private:

            auto ts()->uint64_t {
                return std::chrono::duration_cast<
                        std::chrono::nanoseconds>(
                        std::chrono::high_resolution_clock::now()
                        .time_since_epoch())
                        .count();
            };
            auto ts(uint64_t &counter)->uint64_t {
                return ts() + ts() % ++counter;
            };
            auto len(uint64_t &counter, uint64_t start)->uint64_t {
                return (ts(counter) - start) *
                        std::abs((long long) (ts(counter) - ts(counter))) % FACTOR;
            };

        public:

            auto set_iv(std::vector<string> iv)->generator* {
                if (!iv.empty())
                    this->IV.swap(iv);
                return this;
            };
            auto set_factor(uint64_t v)->generator* {
                if (0 < v)
                    this->FACTOR = v;
                return this;
            };
            auto set_primes(std::vector<uint64_t> primes)->generator* {
                if (!primes.empty())
                    this->PRIMES.swap(primes);
                return this;
            };

        private:

            //uint64_t FACTOR = 89519;
            uint64_t FACTOR = 41;
            std::vector<string> IV = {
                SET_IV,
            };
            std::vector<uint64_t> PRIMES = {
                45212177,
                193877777,
                1019449,
                1123909,
            };

        public:

            static auto instance()->generator* {
                return new generator();
            };

            auto dispose()->void {
                this->~generator();
            };

            generator() {
            };

            generator(const generator& orig) {
            };

            virtual ~generator() {
            };

        };

    };

    // Generation points

    /**
     * Generates random number
     * @param hash_mode
     * @param factor
     * @param primes
     * @param iv
     * @return random double
     */
    auto get(
            int hash_mode = randw::hash_mode::sha512,
            uint64_t factor = 0,
            std::vector<uint64_t> primes = {},
    std::vector<string> iv = {}
    )->double {
        uint64_t c = 0;
        double r = 0;
        randw::lib::generator::instance()
                ->set_factor(factor)
                ->set_primes(primes)
                ->set_iv(iv)
                ->run(c, r, hash_mode)
                ->dispose();
        return r;
    };

    /**
     * Generates vector of random numbers
     * @param int size of vector
     * @param hash_mode
     * @param factor
     * @param primes
     * @param iv
     * @return vector of random numbers
     */
    auto get_many(
            uint16_t size,
            int hash_mode = randw::hash_mode::sha512,
            uint64_t factor = 0,
            std::vector<uint64_t> primes = {},
    std::vector<string> iv = {}
    )->vector<double> {
        if (size > UINT16_MAX)
            throw std::runtime_error(string("Requested list is too long"));
        uint64_t c = 0;
        vector<double> v(size);
        auto gen = randw::lib::generator::instance()
                ->set_factor(factor)
                ->set_primes(primes)
                ->set_iv(iv)
                ;
        for (int i = 0; i < size; i++)
            gen->run(c, v.at(i), hash_mode);
        gen->dispose();
        return v;
    };

    /**
     * Generates random number in the range between min and max numbers
     * @param min
     * @param max
     * @param hash_mode
     * @param factor
     * @param primes
     * @param iv
     * @return random integer
     */
    auto get_range(
            uint64_t min,
            uint64_t max,
            int hash_mode = randw::hash_mode::sha512,
            uint64_t factor = 0,
            std::vector<uint64_t> primes = {},
    std::vector<string> iv = {}
    )->uint64_t {
        if (min >= max)
            throw std::runtime_error(string("Min should be never be greater or equals to max"));
        uint64_t c = 0;
        double r = 0;
        randw::lib::generator::instance()
                ->set_factor(factor)
                ->set_primes(primes)
                ->set_iv(iv)
                ->run(c, r, hash_mode)
                ->dispose();
        return r * (max - min) + min;
    };

    /**
     * Shuffles the vector of integers
     * @param input list of integers
     * @param hash_mode
     * @param factor
     * @param primes
     * @param iv
     * @return shuffled list
     */
    auto get_shuffled_list(
            vector<int> &list,
            int hash_mode = randw::hash_mode::sha512,
            uint64_t factor = 0,
            std::vector<uint64_t> primes = {},
    std::vector<string> iv = {}
    )->vector<int> {
        if (list.empty())
            throw std::runtime_error(string("List is empty"));
        map<double, int> tmp;
        vector<int> res;
        {
            uint64_t c = 0;
            auto gen = randw::lib::generator::instance()
                    ->set_factor(factor)
                    ->set_primes(primes)
                    ->set_iv(iv)
                    ;
            for (auto item : list) {
                double r = 0;
                gen->run(c, r, hash_mode);
                tmp.insert({r, item});
            }
            gen->dispose();
        }
        std::transform(
                tmp.begin(), tmp.end(),
                std::back_inserter(res),
                second(tmp)
                );
        return res;
    };

    /**
     * Generates random string
     * @param size of random string
     * @param symbols for string
     * @param hash_mode
     * @param factor
     * @param primes
     * @param iv
     * @return random string
     */
    auto get_string(
            uint8_t size,
            string symbols = "",
            int hash_mode = randw::hash_mode::sha512,
            uint64_t factor = 0,
            std::vector<uint64_t> primes = {},
    std::vector<string> iv = {}
    )->string {
        if (size > UINT8_MAX)
            throw std::runtime_error(string("Requested string is too long"));
        if (symbols.empty())
            symbols = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_#%&";
        string res(size, ' ');
        for (int i = 0; i < size; i++) res.at(i) =
                symbols.at(get_range(0,
                symbols.size() - 1,
                hash_mode,
                factor,
                primes,
                iv));
        return res;
    }

    namespace bignum {

        /**
         * Generates random OpenSSL BIGNUM pointer
         * @param hash_mode
         * @param factor
         * @param primes
         * @param iv
         * @return BIGNUM*
         */
        auto get(
                int hash_mode = randw::hash_mode::sha512,
                uint64_t factor = 0,
                std::vector<uint64_t> primes = {},
        std::vector<string> iv = {}
        )->BIGNUM* {
            uint64_t c = 0;
            auto gen = randw::lib::generator::instance()
                    ->set_factor(factor)
                    ->set_primes(primes)
                    ->set_iv(iv)
                    ;
            BIGNUM *bn = gen->bn(c, hash_mode);
            gen->dispose();
            return bn;
        }

        /**
         * Generates random OpenSSL BIGNUM represented as decimal string.
         * Conversion from bn2dec to real dec is possible by dividing
         * the result to pow(16,64|128).
         * @param hash_mode
         * @param factor
         * @param primes
         * @param iv
         * @return BIGNUM decimal string
         */
        auto dec(
                int hash_mode = randw::hash_mode::sha512,
                uint64_t factor = 0,
                std::vector<uint64_t> primes = {},
        std::vector<string> iv = {}
        )->string {
            return string(BN_bn2dec(get(
                    hash_mode,
                    factor,
                    primes,
                    iv)));
        }

        /**
         * Generates random OpenSSL BIGNUM represented as hex string
         * @param hash_mode
         * @param factor
         * @param primes
         * @param iv
         * @return BIGNUM hex string
         */
        auto hex(
                int hash_mode = randw::hash_mode::sha512,
                uint64_t factor = 0,
                std::vector<uint64_t> primes = {},
        std::vector<string> iv = {}
        )->string {
            return string(BN_bn2hex(get(
                    hash_mode,
                    factor,
                    primes,
                    iv)));
        }
    }

    namespace uint256 {

        /**
         * Generates uint256_t decimal
         * @param hash_mode: sha256|gost256
         * @param factor
         * @param primes
         * @param iv
         * @return 
         */
        auto get(
                int hash_mode = randw::hash_mode::sha256,
                uint64_t factor = 0,
                std::vector<uint64_t> primes = {},
        std::vector<string> iv = {}
        )->uint256_t {
            return uint256_t(BN_bn2hex(bignum::get(
                    hash_mode,
                    factor,
                    primes,
                    iv)), 16);
        }

    }

};

#endif /* LIBRANDW_CORE_HPP */
