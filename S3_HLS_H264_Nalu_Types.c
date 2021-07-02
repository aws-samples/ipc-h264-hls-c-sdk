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

#include "stdlib.h"

#include "S3_HLS_H264_Nalu_Types.h"

#define S3_HLS_NALU_BYTE_POS                5
#define S3_HLS_H264_NALU_BITS               0x1F

const uint8_t h264_start_code[4] = { 0x00, 0x00, 0x00, 0x01 };

S3_HLS_H264E_NALU_TYPE_E S3_HLS_H264_Nalu_Type(S3_HLS_FRAME_ITEM* item) {
    if(NULL == item->second_part_start && 0 != item->second_part_length) {
        return S3_HLS_H264E_NALU_UNSPECIFIED;
    }

    if(S3_HLS_NALU_BYTE_POS > item->first_part_length + item->second_part_length) {
        return S3_HLS_H264E_NALU_UNSPECIFIED;
    }
    
    int i = 0;
    while(i < item->first_part_length && i < S3_HLS_NALU_BYTE_POS - 1) {
        if(h264_start_code[i] != item->first_part_start[i]) {
            return S3_HLS_H264E_NALU_UNSPECIFIED;
        }
        
        i++;
    }
    
    while(i < S3_HLS_NALU_BYTE_POS - 1) {
        // only enter this piece of code when first part length is not enought for finding the nalu byte
        if(h264_start_code[i] != item->second_part_start[i - item->first_part_length]){
            return S3_HLS_H264E_NALU_UNSPECIFIED;
        }
        
        i++;
    }
    
    if(i > item->first_part_length) {
        return item->second_part_start[i - item->first_part_length] & S3_HLS_H264_NALU_BITS;
    } else {
        return item->first_part_start[i] & S3_HLS_H264_NALU_BITS;
    }
}

