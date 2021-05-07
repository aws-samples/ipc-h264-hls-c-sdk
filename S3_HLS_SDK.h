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

#ifndef __S3_HLS_SDK_H__
#define __S3_HLS_SDK_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* End of #ifdef __cplusplus */

#define S3_HLS_TS_PACKET_LENGTH     188
#define S3_HLS_TS_HEADER_LENGTH     4

#define S3_HLS_PES_HEADER_LENGTH    20

#define S3_HLS_OK                   0
#define S3_HLS_NOT_ENOUGH_MEMORY    -1
#define S3_HLS_INVALID_PID          -2
#define S3_HLS_LOCK_FAILED          -3

#define S3_HLS_PAT_PID              0x0000
#define S3_HLS_VIDEO_PID            0x0100
#define S3_HLS_PMT_PID              0x1000

#define S3_HLS_KEY_FORMAT           "/%04d/%02d/%02d/%02d/%02d/%02d.ts"

typedef enum {
    S3_HLS_H264E_NALU_UNSPECIFIED = 0,
    S3_HLS_H264E_NALU_NON_IDR = 1,
    S3_HLS_H264E_NALU_DPA = 2,
    S3_HLS_H264E_NALU_DPB = 3,
    S3_HLS_H264E_NALU_DPC = 4,
    S3_HLS_H264E_NALU_IDR = 5,
    S3_HLS_H264E_NALU_SEI = 6,
    S3_HLS_H264E_NALU_SPS = 7,
    S3_HLS_H264E_NALU_PPS = 8,
    S3_HLS_H264E_NALU_AUD = 9, // Access Unit Delimeter
    S3_HLS_H264E_NALU_END_SEQ = 10,
    S3_HLS_H264E_NALU_END_STREAM = 11,
    S3_HLS_H264E_NALU_FILLER = 12
} S3_HLS_H264E_NALU_TYPE_E;

/**
 * Allocate buffer used for Transport Stream frames.
 * Currently using pingpong buffer, buffer_size is total size, each time use half of the buffer
 */
int S3_HLS_Initialize(unsigned int buffer_size);

/**
 * Free resources especially for pingpong buffer when finalize
 */
void S3_HLS_Finalize();

/**
 * Use FPS to calculate PCR, PTS, DTS, common FPS are 25, 30 etc.
 * This operation never fail so return void
 */
void S3_HLS_Set_FPS(unsigned char fps);

/**
 * Use frame_type as Segmentation start and trigger segment of stream
 */
void S3_HLS_Set_Segmentation_Frame(S3_HLS_H264E_NALU_TYPE_E frame_type);

/**
 * Max Segmentation frames in a single segment, will trigger segment when counter is greater than or equal to this count
 */
void S3_HLS_Set_Segmentation_Frame_Count(unsigned char frame_count);

/**
 * Put video frame to buffer and may trigger auto commit
 */
int S3_HLS_Put_Frame(unsigned char* frame_addr, unsigned int frame_length);

/**
 * Push the content in buffer to S3 as an object and swap buffer area
 */
void S3_HLS_Write_To_S3();

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* End of #ifdef __cplusplus */

#endif
