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
 
#ifndef __S3_HLS_BUFFER_MGR_H__
#define __S3_HLS_BUFFER_MGR_H__

#include "stdint.h"
#include "time.h"
#include <pthread.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

typedef struct s3_hls_buffer_part_handle_s {
    uint8_t* first_part_start;
    uint32_t first_part_length;
    
    uint8_t* second_part_start;
    uint32_t second_part_length;
    
    time_t timestamp;
} S3_HLS_BUFFER_PART_CTX;

typedef void (*BUFFER_CALL_BACK)(S3_HLS_BUFFER_PART_CTX* ctx);

typedef struct s3_hls_buffer_s {
    uint8_t* buffer_start;
    uint32_t total_length;
    
    uint8_t* used_start;
    uint32_t used_length;
    
    uint8_t* last_flush;
    time_t last_flush_timestamp;

    pthread_mutex_t buffer_lock;

    BUFFER_CALL_BACK call_back;
} S3_HLS_BUFFER_CTX;

/*
 * Buffer manager is a central managememnt of video and audio buffer that is cached for sending to S3
 * Initialize will allocate memory buffer for given size
 */
S3_HLS_BUFFER_CTX* S3_HLS_Initialize_Buffer(uint32_t buffer_size, BUFFER_CALL_BACK function_pointer);

/*
 * Free up memory allocated for buffer
 * After calling finalize, user shoud not use ctx any more
 */
void S3_HLS_Finalize_Buffer(S3_HLS_BUFFER_CTX* ctx);

/*
 * Flush will call the call back function with newly added data in buffer
 * The data is stored in a S3_HLS_BUFFER_PART_CTX struct when calling the call back function
 * Data will have a timestamp of when last Flush is called and passed in
 * If there is no data in buffer, calling flush will only update the timestamp
 */
int32_t S3_HLS_Flush_Buffer(S3_HLS_BUFFER_CTX* ctx);

/*
 * Clear buffer will release buffer that provided by flush buffer
 * After clear the buffer, it can be reused by other input
 */
int32_t S3_HLS_Clear_Buffer(S3_HLS_BUFFER_CTX* buffer_ctx, S3_HLS_BUFFER_PART_CTX* ctx);

/*
 * Put data into buffer
 * Return number of bytes written to buffer if success
 * Return negative error code if failed
 */
int32_t S3_HLS_Put_To_Buffer(S3_HLS_BUFFER_CTX* ctx, uint8_t* data, uint32_t length);

int32_t S3_HLS_Lock_Buffer(S3_HLS_BUFFER_CTX* ctx);

int32_t S3_HLS_Unlock_Buffer(S3_HLS_BUFFER_CTX* ctx);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
