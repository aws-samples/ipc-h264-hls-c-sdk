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

#ifndef __S3_HLS_QUEUE_H__
#define __S3_HLS_QUEUE_H__

#include "stdint.h"
#include "time.h"

#include "S3_HLS_Buffer_Mgr.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

#define S3_HLS_MAX_PARTS_IN_BUFFER      10

typedef struct s3_hls_queue_s {
    S3_HLS_BUFFER_PART_CTX queue[S3_HLS_MAX_PARTS_IN_BUFFER];
    uint8_t queue_pos;
    uint8_t queue_length;
    
    pthread_mutex_t s3_hls_queue_lock;
} S3_HLS_QUEUE_CTX;

S3_HLS_QUEUE_CTX* S3_HLS_Initialize_Queue();

int32_t S3_HLS_Add_To_Queue(S3_HLS_QUEUE_CTX* ctx, uint8_t* first_part, uint32_t first_length, uint8_t* second_part, uint32_t second_length, time_t timestamp);

int32_t S3_HLS_Release_Queue(S3_HLS_QUEUE_CTX* ctx);

int32_t S3_HLS_Finalize_Queue(S3_HLS_QUEUE_CTX* ctx);

int32_t S3_HLS_Get_Item_From_Queue(S3_HLS_QUEUE_CTX* ctx, S3_HLS_BUFFER_PART_CTX* buffer_ctx);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
