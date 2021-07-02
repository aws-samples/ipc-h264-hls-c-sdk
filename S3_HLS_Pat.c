/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
/*
 *. Format:
 *
 *  TS Header               4 bytes
 *      0x47        sync
 *      0x40        payload_start + PID 0x0000
 *      0x00        pid
 *      0x30        contains payload data (0x10 always exists) and adaption field (0x20)
 *      0x00        adaption length field
 *
 *  PAT Header
 *      0x00        table_id 0x00 for PAT
 *      0xb0        0b1 (0x80) for section_syntax_indicator, 0b0 (0x40) fixed, 0b11 (0x30) for reserved fix, 0x0, first 4 bits for section length
 *      0x0d        remaining 8 bits for section length 0x0d = 13
 *      0x00        first 8 bits of transport_stream_id fixed
 *      0x01        last 8 bits of transport_stream_id fixed
 *      0xc1        0b11 (0xC) reserved, 0b00000 (0x3E) version number, 0b1 current_next_indicator 1 means this PAT is valid
 *      0x00        section_number +1 for every section
 *      0x00        last_section_number
 *  
 *      // loop start
 *      0x00        first 8 bits of program number in PMT
 *      0x01        last 8 bits of program number in PMT
 *      0xf0        0b111 reserved 0b10000 first 5 bits of program number in PMT
 *      0x00        last 8 bits of program number in PMT
 *
 *      // CRC
 *      0x2a
 *      0xb1
 *      0x04
 *      0xb2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "S3_HLS_Pat.h"
#include "S3_HLS_Return_Code.h"

// #define S3_HLS_PAT_DEBUG

#ifdef S3_HLS_PAT_DEBUG
#define PAT_DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define PAT_DEBUG(x, ...)
#endif

#define S3_HLS_PAT_HEADER_LENGTH        188

uint8_t const_pat[21] = {   0x47, 0x40, 0x00, 0x10, 0x00, 0x00, 0xb0, 0x0d, 
                            0x00, 0x01, 0xc1, 0x00, 0x00, 0x00, 0x01, 0xf0, 
                            0x00, 0x2a, 0xb1, 0x04, 0xb2};
                                
int8_t m_pat_counter = 0;

int32_t S3_HLS_H264_PAT_Write_To_Buffer(S3_HLS_BUFFER_CTX* buffer_ctx) {
    PAT_DEBUG("Writing PAT\n");
    int32_t ret;

    const_pat[S3_HLS_TS_COUNTER_INDEX] &= 0xF0;
    const_pat[S3_HLS_TS_COUNTER_INDEX] |= (m_pat_counter & 0x0F);
    
    PAT_DEBUG("Put PAT to buffer\n");
    ret = S3_HLS_Put_To_Buffer(buffer_ctx, const_pat, sizeof(const_pat));
    if(0 > ret)
        return ret;
        
    ret = S3_HLS_Put_To_Buffer(buffer_ctx, const_fill_word, S3_HLS_PAT_HEADER_LENGTH - sizeof(const_pat));
    if(0 > ret)
        return ret;

    m_pat_counter++;
    
    return S3_HLS_PAT_HEADER_LENGTH;
}

void S3_HLS_PAT_Reset_Counter() {
    m_pat_counter = 0;
}