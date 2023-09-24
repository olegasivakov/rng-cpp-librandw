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

#include "../vars/crypto/vars_crypto.hpp"
#include "../vars/locale/vars_locale.h"

typedef uint8_t Vint8[BLOCK_SIZE];

using std::map;
using std::string;
using std::vector;

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

    namespace seed_mode {

        enum {
            blind = 0,
            pkcs11
        };
    };

    namespace hash_mode {

        enum {
            gost256 = 0,
            gost512,
            hmac256,
            hmac512,
            md5,
            sha1,
            sha128,
            sha256,
            sha512,
        };
    };

    namespace loc {

        enum {
            // ISO-639-1-based Language Codes

            zhHans = 0, // Chinese (simplified)
            zhHant, // Chinese (traditional)
            cs, // Czech
            en, // English
            fr, // French
            it, // Italian
            ja, // Japanese
            ko, // Korean
            pt, // Portuguese
            es, // Spanish
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

            static auto hash(string const &str, int hashSize = 512)->uint64_t {
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

                if (512 == hashSize) {
                    const int n = 0;
                    std::bitset<sizeof (uint8_t) * 64 - n > bits;
                    for (int i = n; i < 64; i++)
                        for (int j = 0; j < 8; ++j)
                            bits[i - n + j] = bits[i - n + j] ^ (CTX->hash[i] & (1 << j)) != 0;
                    free(buffer);
                    free(CTX);
                    return bits.to_ullong();
                } else {
                    const int n = 32;
                    std::bitset<sizeof (uint8_t) * 64 - n > bits;
                    for (int i = n; i < 64; i++)
                        for (int j = 0; j < 8; ++j)
                            bits[i - n + j] = bits[i - n + j] ^ (CTX->hash[i] & (1 << j)) != 0;
                    free(buffer);
                    free(CTX);
                    return bits.to_ullong();
                }
                return 0;
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
                while (len) {
                    size_t size;
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
                        return to_double(gost::hash(data, 256));
                    case randw::hash_mode::gost512:
                        return to_double(gost::hash(data, 512));

                        // @TODO
                    case randw::hash_mode::hmac256:
                    case randw::hash_mode::hmac512:
                        return 0;

                    case randw::hash_mode::md5:
                        return to_double(to_uint64(md5(data)));
                    case randw::hash_mode::sha1:
                        return to_double(to_uint64(sha1(data)));
                    case randw::hash_mode::sha128:
                        return to_double(to_uint64(sha128(data)));
                    case randw::hash_mode::sha256:
                        return to_double(to_uint64(sha256(data)));
                    case randw::hash_mode::sha512:
                        return to_double(to_uint64(sha512(data)));
                }
                return 0.0;
            };
            static auto hmac(string &key, string& message, int size = 256)->string {
                return "";
            };

        private:

            static auto to_uint64(string const& data)->uint64_t {
                return to_uint64(data.size(), (unsigned char *) data.c_str());
            }

            static auto to_uint64(size_t n, unsigned char * data)->uint64_t {
                uint64_t res = 0;
                size_t b;

                for (b = 0; b < n / 8; ++b) {
                    res <<= 8;
                    res += data[b];
                }

                const size_t r = n % 8;
                res <<= r;
                res += (data[b] >> (8 - r));

                return res;
            };
            static auto to_double(uint64_t hash)->double {
                std::stringstream ss;
                ss << std::fixed << std::setprecision(21) << hash;
                while (ss.str().size() < 21) ss << "0";
                return (double) std::stod(ss.str().substr(0, 21)) / pow(10, 21);
            }

        private:

            static auto md5(string const& data)->string {
                MD5_CTX CTX;
                const int hash_length = MD5_LENGTH;
                char hash[hash_length];
                std::memset(hash, 0, MD5_LENGTH);
                MD5_Init(&CTX);
                MD5_Update(&CTX, (unsigned char *) data.c_str(), data.size());
                MD5_Final((unsigned char *) hash, &CTX);
                return string(hash);
            };
            static auto sha1(string const& data)->string {
                unsigned char hash[SHA_DIGEST_LENGTH];
                SHA_CTX CTX;
                SHA1_Init(&CTX);
                SHA1_Update(&CTX, data.c_str(), data.size());
                SHA1_Final(hash, &CTX);
                std::array<uint8_t, SHA_DIGEST_LENGTH> tmp;
                for (auto i = 0; i < SHA_DIGEST_LENGTH; i++) tmp[i] = hash[i];
                return string(std::begin(tmp), std::end(tmp));
            };
            static auto sha128(string const& data)->string {
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256_CTX CTX;
                SHA256_Init(&CTX);
                SHA256_Update(&CTX, data.c_str(), data.size());
                SHA256_Final(hash, &CTX);
                std::array<uint8_t, 16> tmp;
                for (auto i = 0; i < SHA128_DIGEST_LENGTH; i++) tmp[i] = hash[i * 2];
                return string(std::begin(tmp), std::end(tmp));
            };
            static auto sha256(string const& data)->string {
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256_CTX CTX;
                SHA256_Init(&CTX);
                SHA256_Update(&CTX, data.c_str(), data.size());
                SHA256_Final(hash, &CTX);
                std::array<uint8_t, 32> tmp;
                for (auto i = 0; i < SHA256_DIGEST_LENGTH; i++) tmp[i] = hash[i];
                return string(std::begin(tmp), std::end(tmp));
            };
            static auto sha512(string const& data)->string {
                unsigned char hash[SHA512_DIGEST_LENGTH];
                SHA512_CTX CTX;
                SHA512_Init(&CTX);
                SHA512_Update(&CTX, data.c_str(), data.size());
                SHA512_Final(hash, &CTX);
                std::array<uint8_t, 64> tmp;
                for (auto i = 0; i < SHA512_DIGEST_LENGTH; i++) tmp[i] = hash[i];
                return string(std::begin(tmp), std::end(tmp));
            };

        private:

            static auto hmac128(string const& key, string const& message)->string {
                return hmac256(key, message).substr(0, 32);
            };
            static auto hmac256(string const& key_, string const& message)->string {
                string key(key_.c_str());
                unsigned char hash[SHA256_DIGEST_LENGTH];
                HMAC_CTX *CTX = HMAC_CTX_new();
                HMAC_Init_ex(CTX, (unsigned char *) key.c_str(), key.length(), EVP_sha256(), NULL);
                HMAC_Update(CTX, (unsigned char *) message.c_str(), message.length());
                unsigned int len = SHA256_DIGEST_LENGTH;
                HMAC_Final(CTX, hash, &len);
                HMAC_CTX_free(CTX);
                return string(reinterpret_cast<char*> (hash), len);
            };
            static auto hmac512(string const& key_, string const& message)->string {
                string key(key_.c_str());
                unsigned char hash[SHA512_DIGEST_LENGTH];
                HMAC_CTX *CTX = HMAC_CTX_new();
                HMAC_Init_ex(CTX, &key, key.length(), EVP_sha512(), NULL);
                HMAC_Update(CTX, (unsigned char *) message.c_str(), message.length());
                unsigned int len = SHA512_DIGEST_LENGTH;
                HMAC_Final(CTX, hash, &len);
                HMAC_CTX_free(CTX);
                return string(reinterpret_cast<char*> (hash), len);
            };

        };

        class generator {
        private:

            auto make_str(uint64_t &counter, double &random)->string {
                std::stringstream ss;
                ss
                        << std::fixed << std::setprecision(54)
                        << random << ";"
                        << counter++ << ";"
                        ;
                for (auto var :{
                        ts(),
                        ts(counter),
                        ts(counter) % PRIME1,
                        ts(counter) % PRIME2,
                    })ss << ";" << var;
                // @TODO ss.seekp()
                return ss.str();
            };

        public:

            auto run(uint64_t &counter, double &random, int hash_mode = randw::hash_mode::sha512)->generator* {
                if (UINT8_MAX < counter) counter = 0;

                uint64_t start = ts(counter) + counter++;
                random = randw::lib::hash::get(std::to_string(start));
                for (auto i = 0; i < len(counter, start); i++) {
                    random = randw::lib::hash::get(make_str(counter, random), hash_mode);
                }
                return this;
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
                ++counter;
                return std::chrono::duration_cast<
                        std::chrono::nanoseconds>(
                        std::chrono::high_resolution_clock::now()
                        .time_since_epoch())
                        .count() +
                        std::chrono::duration_cast<
                        std::chrono::nanoseconds>(
                        std::chrono::high_resolution_clock::now()
                        .time_since_epoch())
                        .count() % counter;
            };
            auto len(uint64_t &counter, uint64_t start)->uint64_t {
                int add = ts(counter) - ts(counter);
                if (0 > add) add = add *-1;
                return (ts(counter) - start) * add % FACTOR1;
            };

        public:

            auto set_factor_1(uint64_t v)->generator* {
                this->FACTOR1 = v;
                return this;
            };
            auto set_factor_2(uint64_t v)->generator* {
                this->FACTOR2 = v;
                return this;
            };
            auto set_prime_1(uint64_t v)->generator* {
                this->PRIME1 = v;
                return this;
            };
            auto set_prime_2(uint64_t v)->generator* {
                this->PRIME2 = v;
                return this;
            };

        private:

            uint64_t FACTOR1 = 41,
                    FACTOR2 = 7,
                    PRIME1 = 45212177,
                    PRIME2 = 193877777
                    ;

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
     * Generates PoW-based random number
     * @return random double
     */
    auto get(int hash_mode = randw::hash_mode::sha512)->double {
        uint64_t c = 0;
        double r = 0;
        randw::lib::generator::instance()
                ->run(c, r, hash_mode)
                ->dispose();
        return r;
    };

    /**
     * Generates PoW-based vector of random numbers
     * @param int size of vector
     * @return vector of random numbers
     */
    auto get_many(uint16_t size, int hash_mode = randw::hash_mode::sha512)->vector<double> {
        if (size > UINT16_MAX)
            throw std::runtime_error(string("Requested list is too long"));
        uint64_t c = 0;
        vector<double> v(size);
        auto g = randw::lib::generator::instance();
        for (int i = 0; i < size; i++)
            g->run(c, v.at(i), hash_mode);
        g->dispose();
        return v;
    };

    /**
     * Generates PoW-based random number in the range between min and max numbers
     * @param min
     * @param max
     * @return random integer
     */
    auto get_range(uint64_t min, uint64_t max, int hash_mode = randw::hash_mode::sha512)->uint64_t {
        if (min >= max)
            throw std::runtime_error(string("Min should be never be greater or equals to max"));
        uint64_t c = 0;
        double r = 0;
        uint64_t result = 0;
        randw::lib::generator::instance()
                ->run(c, r, hash_mode)
                ->dispose();
        result = r * (max - min + 2) + min - 1;
        return result;
    };

    /**
     * Shuffles the vector of integers
     * @param input list of integers
     * @return shuffled list
     */
    auto get_shuffled_list(vector<int> &list, int hash_mode = randw::hash_mode::sha512)->vector<int> {
        if (list.empty())
            throw std::runtime_error(string("List is empty"));
        map<double, int> tmp;
        vector<int> res;
        {
            uint64_t c = 0;
            auto g = randw::lib::generator::instance();
            for (auto item : list) {
                double r = 0;
                g->run(c, r, hash_mode);
                tmp.insert({r, item});
            }
            g->dispose();
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
     * @return random string
     */
    auto get_string(uint8_t size, string symbols = "", int hash_mode = randw::hash_mode::sha512)->string {
        if (size > UINT8_MAX)
            throw std::runtime_error(string("Requested string is too long"));
        if (symbols.empty())
            symbols = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_#%&";
        string res(size, ' ');
        for (int i = 0; i < size; i++) res.at(i) =
                symbols.at(get_range(0,
                symbols.size() - 1,
                hash_mode
                ));
        return res;
    }

    /**
     * Generates a seed phrase
     *
     * @param size of seed phrase
     * @param seed mode algorithm
     * <ul>
     * <li>randw::seed_mode::blind</li>
     * <li>randw::seed_mode::pkcs11</li>
     * </ul>
     * @param locale. Supported languages are:
     * <ul>
     * <li>randw::loc::zhHans   //Chinese (simplified)</li>
     * <li>randw::loc::zh   //synonym for Chinese (simplified)</li>
     * <li>randw::loc::zhHant   // Chinese (traditional)</li>
     * <li>randw::loc::cs       // Czech</li>
     * <li>randw::loc::en       // English</li>
     * <li>randw::loc::fr       // French</li>
     * <li>randw::loc::it       // Italian</li>
     * <li>randw::loc::ja       // Japanese</li>
     * <li>randw::loc::ko       // Korean</li>
     * <li>randw::loc::pt       // Portuguese</li>
     * <li>randw::loc::es       // Spanish</li>
     * </ul>
     * @param phrases
     * @return seed phrase as vector of words
     */
    auto get_seed(int size = 12, int mode = randw::seed_mode::blind, int locale = 3, vector<string> phrases = {}, int hash_mode = randw::hash_mode::sha512)->vector<string> {
        if (phrases.empty()) {
            map<int, vector < string >> seeds = {

                {randw::loc::zhHans, randw::lib::locale::zhHans()},
                {randw::loc::zhHans, randw::lib::locale::zhHans()},
                {randw::loc::zhHant, randw::lib::locale::zhHant()},
                {randw::loc::cs, randw::lib::locale::cs()},
                {randw::loc::en, randw::lib::locale::en()},
                {randw::loc::fr, randw::lib::locale::fr()},
                {randw::loc::it, randw::lib::locale::it()},
                {randw::loc::ja, randw::lib::locale::ja()},
                {randw::loc::ko, randw::lib::locale::ko()},
                {randw::loc::pt, randw::lib::locale::pt()},
                {randw::loc::es, randw::lib::locale::es()},

            };

            if (seeds.find(locale) == seeds.end())
                throw std::runtime_error(string("Language not found"));
            phrases = seeds.at(locale);
        }

        /**
         * Blind seed vector
         * @param size
         * @param mode
         * @param locale
         * @param phrases
         * @return
         */
        auto seed_blind = [](int size, int locale, vector<string> phrases, int hash_mode = randw::hash_mode::sha512)->vector<string> {
            vector<string> seed(size);
            for (int i = 0; i < size; i++) seed.at(i) =
                    phrases.at(randw::get_range(0,
                    phrases.size() - 1,
                    hash_mode
                    ));
            return seed;
        };

        /**
         * PKCS#11 seed vector
         * @param size
         * @param mode
         * @param locale
         * @param phrases
         * @return
         */
        auto seed_pkcs11 = [](int size, int locale, vector<string> phrases, int hash_mode = randw::hash_mode::sha512)->vector<string> {
            return {};
        };

        switch (mode) {
            case randw::seed_mode::blind: return seed_blind(size, locale, phrases, hash_mode);
            case randw::seed_mode::pkcs11: return seed_pkcs11(size, locale, phrases, hash_mode);
        }
        throw std::runtime_error(string("Seed generator returns nothing"));
    }

};

#endif /* LIBRANDW_CORE_HPP */