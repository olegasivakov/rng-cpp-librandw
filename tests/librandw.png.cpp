/*
 * The MIT License
 *
 * Copyright 2023 oleg.
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
 * File:   librandw.png.cpp
 * Author: oleg
 *
 * Created on September 3, 2023, 3:16 PM
 */

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <time.h>
#include <map>
#include <vector>
#include <unistd.h>

#include <algorithm>
#include <random>
#include <string>

#include <png.h>

#include "../librandw.hpp"

/*
 * Simple C++ Test Suite
 */

auto png(int file_id, int width = 64, int height = 64)->void {
    FILE *fp = fopen(string("png/").append(std::to_string(file_id)).append(".png").c_str(), "wb");
    png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, 0, 0, 0);
    png_infop info_ptr = png_create_info_struct(png_ptr);
    png_init_io(png_ptr, fp);

    /* write header */
    int depth = 8;
    png_set_IHDR(png_ptr, info_ptr, width, height,
            depth, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE,
            PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

    png_write_info(png_ptr, info_ptr);

    /* write bytes */
    png_bytep *row_pointers = (png_bytep*) malloc(sizeof (png_bytep) * height);
    for (int i = 0; i < height; i++)
        row_pointers[i] = (png_byte*) png_malloc(png_ptr,
            width * 2 * 3);

    for (int y = 0; y < height; y++) {


        std::cout << "ROW\t" << y + 1 << std::endl;


        for (int x = 0; x < width * 3; x += 3) {
            row_pointers[y][x + 0] = (uint8_t) (randw::get() * UINT8_MAX);
            row_pointers[y][x + 1] = (uint8_t) (randw::get() * UINT8_MAX);
            row_pointers[y][x + 2] = (uint8_t) (randw::get() * UINT8_MAX);
        }
    }

    png_set_rows(png_ptr, info_ptr, row_pointers);
    png_write_image(png_ptr, row_pointers);
    png_write_end(png_ptr, NULL);


    /* cleanup heap allocation */
    for (int y = 0; y < height; y++)
        free(row_pointers[y]);
    free(row_pointers);

    fclose(fp);
}

int main(int argc, char** argv) {

    for (int i = 0; i < 12; i++) png(i, 256, 256);

    return (EXIT_SUCCESS);
}

