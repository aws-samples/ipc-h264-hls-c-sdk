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

#ifndef __S3_HLS_H264_NALU_TYPES_H__
#define __S3_HLS_H264_NALU_TYPES_H__

#include "stdint.h"
#include "S3_HLS_SDK.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

typedef enum {
    S3_HLS_H264E_NALU_UNSPECIFIED = 0,
    S3_HLS_H264E_NALU_NON_IDR = 1,
    S3_HLS_H264E_NALU_DPA = 2,
    S3_HLS_H264E_NALU_DPB = 3,
    S3_HLS_H264E_NALU_DPC = 4,
    S3_HLS_H264E_NALU_IDR = 5,
    S3_HLS_H264E_NALU_SEI = 6,
    S3_HLS_H264E_NALU_SPS = 7,
    S3_HLS_H264E_NALU_PPS = 8,
    S3_HLS_H264E_NALU_AUD = 9, // Access Unit Delimeter
    S3_HLS_H264E_NALU_END_SEQ = 10,
    S3_HLS_H264E_NALU_END_STREAM = 11,
    S3_HLS_H264E_NALU_FILLER = 12
} S3_HLS_H264E_NALU_TYPE_E;

S3_HLS_H264E_NALU_TYPE_E S3_HLS_H264_Nalu_Type(S3_HLS_FRAME_ITEM* item);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
