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

#include <pthread.h>

#include "S3_Crypto.h"
#include "S3_HLS_Return_Code.h"

int32_t S3_SHA256_Init(S3_SHA256_CTX* ctx) {
    if(NULL == ctx) {
        return S3_HLS_INVALID_PARAMETER;
    }

    return SHA256_Init(ctx);
}

int32_t S3_SHA256_Update(S3_SHA256_CTX* ctx, const void *data, uint32_t length) {
    if(NULL == ctx) {
        return S3_HLS_INVALID_PARAMETER;
    }

    return SHA256_Update(ctx, data, length);
}

int32_t S3_SHA256_Final(S3_SHA256_CTX *ctx, S3_SHA256_HASH result) {
    if(NULL == ctx) {
        return S3_HLS_INVALID_PARAMETER;
    }

    return SHA256_Final(result, ctx);
}

int32_t S3_HMAC_SHA256(unsigned char* key, unsigned int key_length, char* data, unsigned int data_length, S3_SHA256_HASH result){
    const EVP_MD * engine = EVP_sha256();
    unsigned int ret_length = 0;

    HMAC_CTX* ctx = NULL; 
    ctx = HMAC_CTX_new();	
    if(NULL == ctx) {
        return S3_CRYPTO_FAILED;
    }
        
    HMAC_Init_ex(ctx, key, key_length, engine, NULL);  
    HMAC_Update(ctx, (unsigned char*)data, data_length); 
  
    HMAC_Final(ctx, result, &ret_length);  
  
    HMAC_CTX_free(ctx);

    if(SHA256_DIGEST_LENGTH != ret_length) {
        return S3_CRYPTO_FAILED;
    }

    return S3_CRYPTO_OK;
}
