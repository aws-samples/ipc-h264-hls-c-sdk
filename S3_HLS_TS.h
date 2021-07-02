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

#ifndef __S3_HLS_H264_PMT_H__
#define __S3_HLS_H264_PMT_H__

#include "stdint.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

/*
 * Call this function to write TS header and adoption field to buffer
 */
int32_t S3_HLS_TS_Write_To_Buffer();

/*
 * Call this function to set pid before write TS Header to buffer
 */
void S3_HLS_TS_Set_Pid(uint32_t pid);

/*
 * Call this function to set payload start flag before write TS Header to buffer
 */
void S3_HLS_TS_Set_Payload_Start();

/*
 * Call this function to set random access flag before write TS Header to buffer
 */
void S3_HLS_TS_Set_Random_Access();

/*
 * Call this function to set PCR flag and value before write TS Header to buffer
 */
void S3_HLS_TS_Set_PCR(uint64_t input_timestamp);

/*
 * Call this function to fill adoption fields if data_length is less than remaining bytes. 
 * Call this function before write TS Header to buffer and after set random access and pcr
 */
void S3_HLS_TS_Fill_Remaining_Length(uint32_t data_length);

/*
 * Call this function to reset the counter field in ts header
 */
void S3_HLS_TS_Reset_Counter(uint32_t pid);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
