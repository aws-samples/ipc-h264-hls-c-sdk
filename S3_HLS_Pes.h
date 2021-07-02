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

#ifndef __S3_HLS_H264_PES_H__
#define __S3_HLS_H264_PES_H__

#include "S3_HLS_SDK.h"
#include "S3_HLS_Buffer_Mgr.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

#define ERR_S3_HLS_H264_PES_NULL_BUFFER                 -1
#define ERR_S3_HLS_H264_PES_INVALID_BUFFER_LENGTH       -2

/*
 * write PES header to buffer
 * internal execution will set stream types for different stream type
 * returns number of bytes written to the buffer
 */
int32_t S3_HLS_Pes_Write_Video_Frame(S3_HLS_BUFFER_CTX* ctx, S3_HLS_FRAME_PACK* pack);

/*
 * write PES header to buffer
 * internal execution will set stream types for different stream type
 * returns number of bytes written to the buffer
 */
int32_t S3_HLS_Pes_Write_Audio_Frame(S3_HLS_BUFFER_CTX* ctx, S3_HLS_FRAME_PACK* pack);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
