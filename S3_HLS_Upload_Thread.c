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
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "S3_HLS_Upload_Thread.h"
#include "S3_HLS_Return_Code.h"

//#define S3_HLS_THREAD_DEBUG

#ifdef S3_HLS_THREAD_DEBUG
#define THREAD_DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define THREAD_DEBUG(x, ...)
#endif


static void* S3_HLS_Thread_Loop(void* ctx) {
    THREAD_DEBUG("Thread Initialized!\n");
    if(NULL == ctx) {
        THREAD_DEBUG("Cannot find thread context!\n");
        return NULL;
    }
    
    S3_HLS_THREAD_CTX* thread_ctx = (S3_HLS_THREAD_CTX*)ctx;
    while(!thread_ctx->exit_flag) {
        printf("Thread Run!\n");
        thread_ctx->run();
    }
}

/*
 * Initialize resources and create thread context but not start the thread
 */
S3_HLS_THREAD_CTX* S3_HLS_Upload_Thread_Initialize(THREAD_RUN call_back) {
    if(NULL == call_back)
        return NULL;
        
    THREAD_DEBUG("Creating thread context!\n");
    S3_HLS_THREAD_CTX* ctx = (S3_HLS_THREAD_CTX*)malloc(sizeof(S3_HLS_THREAD_CTX));
    if(NULL == ctx) {
        THREAD_DEBUG("Allocate memory for thread context failed!\n");
        return NULL;
    }
        
    ctx->exit_flag = 0;
    ctx->run = call_back;
    
    THREAD_DEBUG("Creating thread context finished!\n");
	return ctx;
}

/*
 * Start thread in given thread ctx
 */
int32_t S3_HLS_Upload_Thread_Start(S3_HLS_THREAD_CTX* ctx) {
    if(NULL == ctx)
        return S3_HLS_INVALID_PARAMETER;
        
    THREAD_DEBUG("Starting thread!\n");
    int32_t ret = pthread_create(&ctx->thread_id, NULL, (void*)S3_HLS_Thread_Loop, ctx);
	if(0 != ret) {
	    free(ctx);
        return S3_HLS_UNKNOWN_INTERNAL_ERROR;
	}

    THREAD_DEBUG("Starting thread finished %d!\n", ctx->thread_id);
	
	return S3_HLS_OK;
}

/*
 * Stop thread and free ctx object
 * User should not use ctx after calling this function
 */
int32_t S3_HLS_Upload_Thread_Stop(S3_HLS_THREAD_CTX* ctx) {
    if(NULL == ctx)
        return S3_HLS_INVALID_PARAMETER;
        
    if(ctx->exit_flag)
        return S3_HLS_THREAD_ALREADY_STOPPED;
    
    ctx->exit_flag = 1;
    
    pthread_join(ctx->thread_id, NULL);
    
    free(ctx);
    
    return S3_HLS_OK;
}
