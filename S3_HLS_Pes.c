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

/*
    *buffer++ = 0; // 3 bytes start code
    *buffer++ = 0;
    *buffer++ = 1;
    *buffer++ = 0xe0; // stream id for video is 0xe0, audio would be 0xc0
    *buffer++ = 0; // 2 bytes packet length
    *buffer++ = 0;
    *buffer++ = 0x80; // 0b10 + 6 bits flags PTS exists but no DTS
    *buffer++ = 0x80; // indicate have pts and no dts
    *buffer++ = 0x05;
    
    // write pts
    *buffer++ = 0x21 | ((m_pts_timestamp >> 29) & 0x0e);
    *buffer++ = (m_pts_timestamp >> 22) & 0xff;
    *buffer++ = 0x01 | ((m_pts_timestamp >> 14) & 0xfe);
    *buffer++ = (m_pts_timestamp >> 7) & 0xff;
    *buffer++ = 0x01 | (m_pts_timestamp & 0xfe);
    
    // means sequence end
    *buffer++ = 0;
    *buffer++ = 0;
    *buffer++ = 0;
    *buffer++ = 1;

    *buffer++ = 0x09;
    *buffer++ = 0xf0;
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "S3_HLS_Pes.h"
#include "S3_HLS_Return_Code.h"
#include "S3_HLS_H264_Nalu_Types.h"

#include "S3_HLS_Pat.h"
#include "S3_HLS_Pmt.h"
#include "S3_HLS_TS.h"

//#define S3_HLS_PES_DEBUG

#ifdef S3_HLS_PES_DEBUG
#define PES_DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define PES_DEBUG(x, ...)
#endif

// #define S3_HLS_PES_AUDIO_DEBUG

#ifdef S3_HLS_PES_AUDIO_DEBUG
#define AUDIO_DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define AUDIO_DEBUG(x, ...)
#endif

#define S3_HLS_PES_PTS_START    9

#define S3_HLS_FALSE            0
#define S3_HLS_TRUE             1

#define S3_HLS_PES_VIDEO_CODE           0xe0
#define S3_HLS_PES_AUDIO_CODE           0xc0

static uint8_t video_pes_header[20] = { 0x00, 0x00, 0x01, /* 3 bytes start code of PES */
                                        0xe0, /* Stream type (0xc0) */ 
                                        0x00, 0x00, /* Packet Length, 0x00, 0x00 for video, data length for audio*/
                                        0x80, 0x80, /* PTS, DTS flags*/
                                        0x05, /* PES Header Data Length 5 for 5 bytes of PTS */
                                        0x00, 0x00, 0x00, 0x00, 0x00, /* PTS field */
                                        // below only for video
                                        0x00, 0x00, 0x00, 0x01, /* H264 Start Code */
                                        0x09, 0xF0 /* H264 Sequence End */    
                                      };

static uint8_t audio_pes_header[14] = { 0x00, 0x00, 0x01, /* 3 bytes start code of PES */
                                        0xe0, /* Stream type (0xc0) */ 
                                        0x00, 0x00, /* Packet Length, 0x00, 0x00 for video, data length for audio*/
                                        0x80, 0x80, /* PTS, DTS flags*/
                                        0x05, /* PES Header Data Length 5 for 5 bytes of PTS */
                                        0x00, 0x00, 0x00, 0x00, 0x00 /* PTS field */
                                      };
                            
// every 2 video frame packs may need increase if < 20 FPS
static uint8_t pcr_count = 0;
static const uint8_t pcr_count_interval = 2;

// every 3 video frame packs
static uint8_t pat_pmt_count = 0;
static const uint8_t pat_pmt_interval = 3;

// may need to modify according to 
static S3_HLS_H264E_NALU_TYPE_E seperate_nalu_type = S3_HLS_H264E_NALU_SPS;

static uint8_t seperate_count = 0;
static const uint8_t seperate_count_interval = 1;

static uint8_t first_call = 1;

static uint8_t has_error = 0;

int32_t S3_HLS_Pes_Write_Video_Pes(S3_HLS_BUFFER_CTX* buffer_ctx, uint64_t input_timestamp) {
    uint64_t timestamp = input_timestamp / 100 * 9 + 63000;
    
    video_pes_header[9] = 0x21 | ((timestamp >> 29) & 0x0e);
    video_pes_header[10] = (timestamp >> 22) & 0xff;
    video_pes_header[11] = 0x01 | ((timestamp >> 14) & 0xfe);
    video_pes_header[12] = (timestamp >> 7) & 0xff;
    video_pes_header[13] = 0x01 | (timestamp & 0xfe);

    return S3_HLS_Put_To_Buffer(buffer_ctx, video_pes_header, sizeof(video_pes_header));
}

int32_t S3_HLS_Pes_Write_Audio_Pes(S3_HLS_BUFFER_CTX* buffer_ctx, uint64_t input_timestamp, uint32_t packet_length) {
    packet_length += sizeof(audio_pes_header) - 6;
    
    audio_pes_header[4] = ((packet_length >> 8) & 0xFF);
    audio_pes_header[5] = (packet_length & 0xFF);

    uint64_t timestamp = input_timestamp / 100 * 9 + 63000;
    
    audio_pes_header[9] = 0x21 | ((timestamp >> 29) & 0x0e);
    audio_pes_header[10] = (timestamp >> 22) & 0xff;
    audio_pes_header[11] = 0x01 | ((timestamp >> 14) & 0xfe);
    audio_pes_header[12] = (timestamp >> 7) & 0xff;
    audio_pes_header[13] = 0x01 | (timestamp & 0xfe);
    
    return S3_HLS_Put_To_Buffer(buffer_ctx, audio_pes_header, sizeof(audio_pes_header));
}

int32_t S3_HLS_Pes_Write_Video_Frame(S3_HLS_BUFFER_CTX* buffer_ctx, S3_HLS_FRAME_PACK* pack) {
    int32_t ret = S3_HLS_OK;

    uint8_t random_access = S3_HLS_FALSE;
    uint8_t has_pcr = S3_HLS_FALSE;
    uint32_t content_length = 0;
    
    if(0 == pack->item_count) {
        PES_DEBUG("[Pes - Video] Invalid Packet Count!\n");
        return S3_HLS_INVALID_PARAMETER;
    }
    
    if (0 != S3_HLS_Lock_Buffer(buffer_ctx)) {// lock failed
        PES_DEBUG("[Pes - Video] Lock Buffer Failed!\n");
        return S3_HLS_LOCK_FAILED;
    }
        
    if(first_call) {
        PES_DEBUG("[Pes - Video] First Call Flush Buffer!\n");
        S3_HLS_Flush_Buffer(buffer_ctx); // only update last timestamp
        first_call = 0;
    }

    for(uint32_t cnt = 0; cnt < pack->item_count; cnt++) {
        if(NULL == pack->items[cnt].first_part_start || (NULL == pack->items[cnt].second_part_start && pack->items[cnt].second_part_length != 0)) {
            ret = S3_HLS_INVALID_PARAMETER;
            goto l_exit;
        }

        S3_HLS_H264E_NALU_TYPE_E frame_type = S3_HLS_H264_Nalu_Type(&pack->items[cnt]);
        if(seperate_nalu_type == frame_type) {
            PES_DEBUG("[Pes - Video] Nalu: %d\n", frame_type);
            if(seperate_count_interval == seperate_count) {
                PES_DEBUG("[Pes - Video] Need Seperate\n");
                has_error = 0;
                ret = S3_HLS_Flush_Buffer(buffer_ctx);
                if(0 > ret) {
                    PES_DEBUG("[Pes - Video] Flush Buffer Failed!\n");
                    goto l_exit;
                }

                seperate_count = 0;
                pat_pmt_count = 0;
            }
            
            seperate_count++;
        }
        
        if(S3_HLS_H264E_NALU_IDR == frame_type) {
            random_access = S3_HLS_TRUE;
        }
        
        content_length += pack->items[cnt].first_part_length + pack->items[cnt].second_part_length;
    }

    PES_DEBUG("[Pes - Video] Video Stream Length %d\n", content_length);
    if(has_error) {
        PES_DEBUG("[pes - Video] Prev error detected, skip until next sperate frame!\n");
        goto l_exit;
    }
    content_length += sizeof(video_pes_header); // calculate total length

    // decide whether write pat & pmt
    if(0 == pat_pmt_count) {
        ret = S3_HLS_H264_PAT_Write_To_Buffer(buffer_ctx);
        if(0 > ret) {
            has_error = 1;
            PES_DEBUG("[Pes - Video] Write PAT Failed!\n");
            goto l_exit;
        }
        
        ret = S3_HLS_H264_PMT_Write_To_Buffer(buffer_ctx);
        if(0 > ret) {
            has_error = 1;
            PES_DEBUG("[Pes - Video] Write PAT Failed!\n");
            goto l_exit;
        }
    }
    
    // update counter
    pat_pmt_count++;
    if(pat_pmt_interval == pat_pmt_count) {
        pat_pmt_count = 0;
    }
    
    if(0 == pcr_count) {
        has_pcr = S3_HLS_TRUE;
        pcr_count++;
        if(pcr_count_interval == pcr_count) {
            pcr_count = 0;
        }
    }
    
    S3_HLS_TS_Set_Pid(S3_HLS_Video_PID);
    
    S3_HLS_TS_Set_Payload_Start();
    
    if(random_access) {
        S3_HLS_TS_Set_Random_Access();
    }
    
    if(has_pcr) {
        S3_HLS_TS_Set_PCR(pack->items[0].timestamp);
    }
    
    S3_HLS_TS_Fill_Remaining_Length(content_length);

    PES_DEBUG("[Pes - Video] Write TS Header %d\n", content_length);
    // write TS header
    ret = S3_HLS_TS_Write_To_Buffer(buffer_ctx);
    
    if(0 > ret) { // write error
        has_error = 1;
        goto l_exit;
    }
    
    uint32_t remaining = S3_HLS_TS_PACKET_SIZE - ret;
    PES_DEBUG("[Pes - Video] Remaining Size %d\n", remaining);
    
    // write PES info
    ret = S3_HLS_Pes_Write_Video_Pes(buffer_ctx, pack->items[0].timestamp);
    if(0 > ret) {
        has_error = 1;
        goto l_exit;
    }
    
    remaining -= ret;
    content_length -= ret;

    uint32_t packet_index = 0;
    uint32_t packet_pos = 0;
    
    while(content_length > 0) { // have data to send
        PES_DEBUG("[Pes - Video] Remaining Size %d Content Length %d\n", remaining, content_length);
        if(0 == remaining) { // start new ts header
            PES_DEBUG("[Pes - Video] Start New TS Fragment\n");
            S3_HLS_TS_Set_Pid(S3_HLS_Video_PID);
            S3_HLS_TS_Fill_Remaining_Length(content_length);
            ret = S3_HLS_TS_Write_To_Buffer(buffer_ctx);
            PES_DEBUG("[Pes - Video] TS Header used %d\n", ret);
            if(0 > ret) {
                has_error = 1;
                goto l_exit;
            }
            
            remaining = S3_HLS_TS_PACKET_SIZE - ret;
        }
        
        if(remaining > 0) {
            // write data to buffer
            uint8_t* start_pos;
            uint32_t write_length;
            
            if(packet_pos >= pack->items[packet_index].first_part_length) { // writing second part
                // need to copy from second part
                start_pos = pack->items[packet_index].second_part_start + (packet_pos - pack->items[packet_index].first_part_length);
                write_length = remaining < (pack->items[packet_index].first_part_length + pack->items[packet_index].second_part_length - packet_pos) ? remaining : (pack->items[packet_index].first_part_length + pack->items[packet_index].second_part_length - packet_pos);
                PES_DEBUG("Write From Second Part %d, %d, %d, %d, %d\n", remaining, write_length, pack->items[packet_index].first_part_length, pack->items[packet_index].second_part_length, packet_pos);
            } else { // writing first part
                start_pos = pack->items[packet_index].first_part_start + packet_pos;
                write_length = remaining < (pack->items[packet_index].first_part_length - packet_pos) ? remaining : (pack->items[packet_index].first_part_length - packet_pos);
                PES_DEBUG("Write From First Part %d, %d, %d, %d\n", remaining, write_length, pack->items[packet_index].first_part_length, packet_pos);
            }
            
            ret = S3_HLS_Put_To_Buffer(buffer_ctx, start_pos, write_length);
            PES_DEBUG("Write Buffer Ret %d\n", ret);
            
            if(0 > ret) {
                has_error = 1;
                goto l_exit;
            }
            
            content_length -= write_length;
            remaining -= write_length;
            
            packet_pos += write_length;

            PES_DEBUG("[Pes - Video] After Put: Remaining Size %d Content Length %d Packet Pos %d\n", remaining, content_length, packet_pos);
            
            if(packet_pos == pack->items[packet_index].first_part_length + pack->items[packet_index].second_part_length) {
                PES_DEBUG("Goto Next Packet Remaining: %d\n", remaining);
                packet_index++;
                packet_pos = 0;
            }
        }
    }
    
    S3_HLS_Unlock_Buffer(buffer_ctx);

    return S3_HLS_OK;
    
l_exit:
    S3_HLS_Unlock_Buffer(buffer_ctx);

    return ret;
}

int32_t S3_HLS_Pes_Write_Audio_Frame(S3_HLS_BUFFER_CTX* buffer_ctx, S3_HLS_FRAME_PACK* pack) {
    int32_t ret = S3_HLS_OK;

    uint32_t content_length = 0;
    
    AUDIO_DEBUG("[Pes - Audio] Check Cnt\n");
    if(0 == pack->item_count) {
        return S3_HLS_INVALID_PARAMETER;
    }
    
    AUDIO_DEBUG("[Pes - Audio] Try Lock\n");
    if (0 != S3_HLS_Lock_Buffer(buffer_ctx)) // lock failed
        return S3_HLS_LOCK_FAILED;

    AUDIO_DEBUG("[Pes - Audio] Locked\n");
    for(uint32_t cnt = 0; cnt < pack->item_count; cnt++) {
        AUDIO_DEBUG("[Pes - Audio] Packet Item %d, %d, %d\n", pack->item_count, pack->items[cnt].first_part_length, pack->items[cnt].second_part_length);
        if(NULL == pack->items[cnt].first_part_start || (NULL == pack->items[cnt].second_part_start && pack->items[cnt].second_part_length != 0)) {
            ret = S3_HLS_INVALID_PARAMETER;
            goto l_exit;
        }

        content_length += pack->items[cnt].first_part_length + pack->items[cnt].second_part_length;
    }

    content_length += sizeof(audio_pes_header); // calculate total length

    AUDIO_DEBUG("[Pes - Audio] Total Length: %d\n", content_length);
    if(has_error) {
        AUDIO_DEBUG("[Pes - Audio] Prev error detected, skip until next sperate frame!\n");
        goto l_exit;
    }

    S3_HLS_TS_Set_Pid(S3_HLS_Audio_PID);
    
    S3_HLS_TS_Set_Payload_Start();
    
    S3_HLS_TS_Set_Random_Access();

    S3_HLS_TS_Fill_Remaining_Length(content_length);

    AUDIO_DEBUG("[Pes - Audio] Write TS Header\n");
    // write TS header
    ret = S3_HLS_TS_Write_To_Buffer(buffer_ctx);
    
    if(0 > ret) { // write error
        AUDIO_DEBUG("[Pes - Audio] Write Buffer Failed! %d\n", ret);
        goto l_exit;
    }
    
    uint32_t remaining = S3_HLS_TS_PACKET_SIZE - ret;
    
    AUDIO_DEBUG("[Pes - Audio] Write Audio PES Header, Remaining: %d\n", remaining);
    // write PES info
    ret = S3_HLS_Pes_Write_Audio_Pes(buffer_ctx, pack->items[0].timestamp, content_length - sizeof(audio_pes_header));
    if(0 > ret) {
        has_error = 1;
        goto l_exit;
    }
    
    remaining -= ret;
    content_length -= ret;

    uint32_t packet_index = 0;
    uint32_t packet_pos = 0;
    
    AUDIO_DEBUG("[Pes - Audio] Write Audio Content\n");
    while(content_length > 0) { // have data to send
        AUDIO_DEBUG("[Pes - Audio] Remaining Size %d Content Length %d\n", remaining, content_length);
        if(0 == remaining) {
            S3_HLS_TS_Set_Pid(S3_HLS_Audio_PID);
            S3_HLS_TS_Fill_Remaining_Length(content_length);
            ret = S3_HLS_TS_Write_To_Buffer(buffer_ctx);
            if(0 > ret) {
                has_error = 1;
                AUDIO_DEBUG("[Pes - Audio] Write Buffer Failed 2! %d\n", ret);
                goto l_exit;
            }
            
            remaining = S3_HLS_TS_PACKET_SIZE - ret;
        }
        
        if(remaining > 0) {
            // write data to buffer
            uint8_t* start_pos;
            uint32_t write_length;
            
            if(packet_pos >= pack->items[packet_index].first_part_length) { // writing second part
                // need to copy from second part
                start_pos = pack->items[packet_index].second_part_start + (packet_pos - pack->items[packet_index].first_part_length);
                write_length = remaining < (pack->items[packet_index].first_part_length + pack->items[packet_index].second_part_length - packet_pos) ? remaining : (pack->items[packet_index].first_part_length + pack->items[packet_index].second_part_length - packet_pos);
            } else { // writing first part
                start_pos = pack->items[packet_index].first_part_start + packet_pos;
                write_length = remaining < (pack->items[packet_index].first_part_length - packet_pos) ? remaining : (pack->items[packet_index].first_part_length - packet_pos);
            }
            
            ret = S3_HLS_Put_To_Buffer(buffer_ctx, start_pos, write_length);
            
            if(0 > ret) {
                has_error = 1;
                AUDIO_DEBUG("[Pes - Audio] Write Buffer Failed 3! %d\n", ret);
                goto l_exit;
            }

            content_length -= write_length;
            remaining -= write_length;
            
            packet_pos += write_length;
            
            if(packet_pos == pack->items[packet_index].first_part_length + pack->items[packet_index].second_part_length) {
                packet_index++;
                packet_pos = 0;
            }
        }
    }
    
    S3_HLS_Unlock_Buffer(buffer_ctx);
    return S3_HLS_OK;

l_exit:
    S3_HLS_Unlock_Buffer(buffer_ctx);
    return ret;
}
