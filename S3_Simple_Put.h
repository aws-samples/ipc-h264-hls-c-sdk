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

#ifndef __S3_REQUEST_H__
#define __S3_REQUEST_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

#define S3_SIMPLE_PUT_OK                        0
#define S3_SIMPLE_PUT_NOT_ENOUGHT_MEMORY        -1
#define S3_SIMPLE_RUNTIME_ERROR                 -2
#define S3_SIMPLE_PUT_CREATE_SOCKET_FAILED      -3
#define S3_SIMPLE_PUT_CONNECT_FAILED            -4
#define S3_SIMPLE_PUT_SEND_DATA_FAILED          -5

/**
 * Initialize S3 put, input parameters including AK/SK and optionally the token used for temporary credential, the region to upload and the bucket name and user defined prefix
 */
void S3_Put_Initialize(char* ak, char* sk, char* token, char* region, char* bucket, char* prefix);

/**
 * Clean up resources before exit
 */
void S3_Put_Finalize();

/**
 * This is used for upload object. The prefix will be added to the key.
 */
int S3_Put_Object(char* object_key, unsigned char* payload, unsigned int size);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
