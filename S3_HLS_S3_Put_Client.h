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

#ifndef __S3_HLS_S3_PUT_CLIENT_H__
#define __S3_HLS_S3_PUT_CLIENT_H__

#include <stdint.h>
#include <pthread.h>

#include "curl/curl.h"

#define S3_HLS_MAX_KEY_LENGTH               1024

#define S3_HLS_TIMESTAMP_HEADER_BUFFER_SIZE 28      // "%04d%02d%02dT%02d%02d%02dZ"
#define S3_HLS_DATE_BUFFER_SIZE             9       // "%04d%02d%02d"
#define S3_HLS_CONTENT_HASH_HEADER_LENGTH   86      // x-amz-content-sha256:......

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

typedef struct s3_hls_client_s {
    char* endpoint;
    uint8_t free_endpoint;
    
    char* uri;
    
    char timestamp_buffer[S3_HLS_TIMESTAMP_HEADER_BUFFER_SIZE];
    char date_buffer[S3_HLS_DATE_BUFFER_SIZE];
    char object_key[S3_HLS_MAX_KEY_LENGTH];
    
    char* host_header;
    
    char content_hash[S3_HLS_CONTENT_HASH_HEADER_LENGTH];

    char* string_to_sign;

    char* region;
    
    char* secret_access_key;
    uint32_t secret_access_key_length;
    
    char* token_header;
    uint32_t token_header_length;

    char* auth_header;
    uint32_t auth_header_length;
    
    char* access_key;
    
    char* tag_header;
    uint32_t tag_header_length;
    
    pthread_mutex_t credential_lock;

    CURL* curl;
} S3_HLS_CLIENT_CTX;

/*
 *
 */
S3_HLS_CLIENT_CTX* S3_HLS_Client_Initialize(char* region, char* bucket, char* endpoint);

/*
 *
 */
int32_t S3_HLS_Client_Finalize(S3_HLS_CLIENT_CTX* ctx);

/*
 *
 */
int32_t S3_HLS_Client_Set_Tag(S3_HLS_CLIENT_CTX* ctx, char* object_tag);

/*
 *
 */
int32_t S3_HLS_Client_Set_Credential(S3_HLS_CLIENT_CTX* ctx, char* ak, char* sk, char* token);

/*
 *
 */
int32_t S3_HLS_Client_Upload_Buffer(S3_HLS_CLIENT_CTX* ctx, char* object_key, char* first_data, uint32_t first_length, char* second_data, uint32_t second_length);

/*
 *
 */
int32_t S3_HLS_Client_Upload_Object(S3_HLS_CLIENT_CTX* ctx, char* object_key, char* data, uint32_t length);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
