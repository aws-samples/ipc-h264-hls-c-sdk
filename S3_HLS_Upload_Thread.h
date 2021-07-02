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

#ifndef __S3_HLS_UPLOAD_THREAD_H__
#define __S3_HLS_UPLOAD_THREAD_H__

#include "stdint.h"
#include "pthread.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

typedef void (*THREAD_RUN)();

typedef struct s3_hls_thread_s {
    pthread_t thread_id;
    uint8_t exit_flag;

    THREAD_RUN run;
} S3_HLS_THREAD_CTX;

/*
 * Initialize resources and create thread context but not start the thread
 */
S3_HLS_THREAD_CTX* S3_HLS_Upload_Thread_Initialize(THREAD_RUN call_back);

/*
 * Start thread in given thread ctx
 */
int32_t S3_HLS_Upload_Thread_Start(S3_HLS_THREAD_CTX* ctx);

/*
 * Stop thread and free ctx object
 * User should not use ctx after calling this function
 */
int32_t S3_HLS_Upload_Thread_Stop(S3_HLS_THREAD_CTX* ctx);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
