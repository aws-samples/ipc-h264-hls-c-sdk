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

#ifndef __S3_CRYPTO_H__
#define __S3_CRYPTO_H__

#include "stdint.h"

#include "openssl/evp.h"
#include "openssl/sha.h"
#include "openssl/hmac.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

#define S3_CRYPTO_OK                    0
#define S3_CRYPTO_FAILED                -1
#define S3_SHA256_DIGEST_LENGTH         32

typedef SHA256_CTX S3_SHA256_CTX;
typedef HMAC_CTX   S3_HMAC_SHA256_CTX;

typedef unsigned char S3_SHA256_HASH[S3_SHA256_DIGEST_LENGTH];

int32_t S3_SHA256_Init(S3_SHA256_CTX* ctx);

int32_t S3_SHA256_Update(S3_SHA256_CTX* ctx, const void *data, uint32_t length);

int32_t S3_SHA256_Final(S3_SHA256_CTX *ctx, S3_SHA256_HASH result);

int32_t S3_HMAC_SHA256(const void* key, unsigned int key_length, const void* data, unsigned int data_length, S3_SHA256_HASH result);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif

