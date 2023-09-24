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
 * File:   vars.locale.h
 * Author: @olegasivakov
 *
 * Created on September 2, 2023, 8:53 PM
 */

#pragma once

#include <string>
#include <vector>

namespace randw {
    namespace lib {
        namespace locale {

            /**
             * BIP-0039 Wordslist (Chinese Simplified)
             * @return
             */
            std::vector<std::string> zhHans();

            /**
             * BIP-0039 Wordslist (Chinese Traditional)
             * @return
             */
            std::vector<std::string> zhHant();

            /**
             * BIP-0039 Wordslist (Czech)
             * @return
             */
            std::vector<std::string> cs();

            /**
             * BIP-0039 Wordslist (English)
             * @return
             */
            std::vector<std::string> en();

            /**
             * BIP-0039 Wordslist (French)
             * @return
             */
            std::vector<std::string> fr();

            /**
             * BIP-0039 Wordslist (Italian)
             * @return
             */
            std::vector<std::string> it();

            /**
             * BIP-0039 Wordslist (Japanese)
             * @return
             */
            std::vector<std::string> ja();

            /**
             * BIP-0039 Wordslist (Korean)
             * @return
             */
            std::vector<std::string> ko();

            /**
             * BIP-0039 Wordslist (Portuguese)
             * @return
             */
            std::vector<std::string> pt();

            /**
             * BIP-0039 Wordslist (Spanish)
             * @return
             */
            std::vector<std::string> es();

        }
    }
}
