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
 *. Format:
 * 
 *. Sync_word;                                          // 8 bits       0x47
 *  transport_error;                                    // 1 bit        0b0 (0x80)
 *  payload_start;                                      // 1 bit        0b0 (0x40)
 *  transport_priority;                                 // 1 bit        0b0 (0x20)
 *  pid;                                                // 13 bits      0x1FFF range, 0x0000 for PAT 0x1000 for PMT 0x0100 for video 0x0101 for audio
 *  scrambling_control;                                 // 2 bits       0b00 (0xC0)
 *  adaptation_field;                                   // 2 bits       0b?1 (0x30 or 0x10)
 *  counter;                                            // 4 bits       0b0000 (0x0F)
 *  
 *  // adaption part
 *  adaption_length;                                    // 8 bits       only exists when adaptation_field & 0x20
 *  
 *  discontinuity;                                      // 1 bit        0b0 (0x80)
 *  random_access;                                      // 1 bit        0b? (0x40) set by user
 *  stream_priority;                                    // 1 bit        0b0 (0x20)
 *  
 *  pcr_field;                                          // 1 bit        0b0 (0x10) when 1 will have 48 bits PCR
 *  opcr_filed;                                         // 1 bit        0b0 (0x08) when 1 will have 48 bits OPCR
 *  splicing_point_flag;                                // 1 bit        0b0 (0x04) when 1 will have 8 bits splice count down
 *  transport_private_data_flag;                        // 1 bit        0b0 (0x02) when 1 will have 8 bits private data length and 8*n bits of private data
 *  adaptation_field_extension_flag;                    // 1 bit        0b0 (0x01) when 1 will have 8 bits adaption field entension length
 *  
 *  // when pcr_field = 1                               // 48 bits
 *  pcr_high[33];
 *  pcr_reserved[6];
 *  pcr_low[9];
 *
 *  // when opcr_field = 1                              // 48 bits
 *  opcr_high[33];
 *  opcr_reserved[6];
 *  opcr_low[9];
 *  
 *  // when splicing_point_flag = 1
 *  splice_countdown;                                   // 8 bits
 *  
 *  // when transport_private_data_flag = 1
 *  private_data_length;                                // 8 bits
 *  private_data[private_data_length];                  // 8 * private_data_length bits
 *  
 *  // when adaptation_field_extension_flag = 1
 *  adaptation_field_extension_length;                  // 8 bits
 *  
 *  ltw_flag;                                           // 1 bit
 *  piecewise_rate_flag;                                // 1 bit
 *  seamless_splice_flag;                               // 1 bit
 *  reserved;                                           // 5 bits
 *  
 *  // when ltw_flag = 1
 *  ltw_valid_flag;                                     // 1 bit
 *  ltw_offset;                                         // 15 bits
 *  
 *  // when piecewise_rate_flag = 1
 *  reserved;                                           // 2 bits
 *  piecewise_rate_flag;                                // 22 bits
 *  
 *  // when seamless_splice_flag = 1
 *  splice_type;                                        // 4 bits
 *  dts_next_au_32_30;                                  // 3 bits
 *  marker_bit;                                         // 1 bit
 *  dts_next_au_29_15;                                  // 15 bits
 *  marker_bit;                                         // 1 bit
 *  dts_next_au_14_0;                                   // 15 bits
 *  marker_bit;                                         // 1 bit
 *  
 *  // to end of adaptation_field_extension_length
 *  unsigned char reserved;                             // 
 *  
 *  // to end of adaption_length
 *  unsigned char stuffing_bytes;                       // 0xFF
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "S3_HLS_TS.h"
#include "S3_HLS_Buffer_Mgr.h"
#include "S3_HLS_Return_Code.h"

#define S3_HLS_TS_PAYLOAD_START_POS         1
#define S3_HLS_TS_PID_HIGH_POS              1
#define S3_HLS_TS_PID_LOW_POS               2
#define S3_HLS_TS_ADOPTION_FLAG_POS         3
#define S3_HLS_TS_ADOPTION_LENGTH_POS       4
#define S3_HLS_TS_RANDOM_ACCESS_FLAG_POS    5
#define S3_HLS_TS_PCR_FLAG_POS              5

#define S3_HLS_PCR_START_POS                6

#define S3_HLS_TS_PAYLOAD_START_FLAG    0x40
#define S3_HLS_TS_PID_HEX_CODE          0x1FFF
#define S3_HLS_TS_RANDOM_ACCESS_FLAG    0x40
#define S3_HLS_TS_PCR_FLAG              0x10
#define S3_HLS_TS_ADOPTION_FLAG         0x20

// #define S3_HLS_TS_DEBUG

#ifdef S3_HLS_TS_DEBUG
#define TS_DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define TS_DEBUG(x, ...)
#endif

uint8_t ts_header[12] = {   0x47, /* Start Code */
                            0x00, /* 3 bit flags only 0x40 is used as payload start, other 5 bits are first 5 bits of PID */
                            0x00, /* last 8 bits of pid 0x100 is video ,0x101 is audio */
                            0x10, /* 0x30 has adoption field, 0x10 doesn't have aoption field, and last 4 bits are ts counter  */
                            
                            0x00, /* adoption length only exists when 4th bytes contains 0x20 flag */
                            
                            0x00, /* adoption flag fields only exists when 5th bytes >= 1 */
                            
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /* PCR field only exists when */
                        }; // last 4 bytes are crc

int8_t m_ts_video_counter = 0; 
int8_t m_ts_audio_counter = 0; 


/*
 * Clear flags and prepare for next TS header
 * Call this function after write to buffer
 */
void S3_HLS_TS_Reset_Header_Info() {
    ts_header[1] = 0;
    ts_header[2] = 0;
    ts_header[3] = 0x10;
    ts_header[4] = 0;
    ts_header[5] = 0;
    ts_header[6] = 0;
    ts_header[7] = 0;
    ts_header[8] = 0;
    ts_header[9] = 0;
    ts_header[10] = 0;
    ts_header[11] = 0;
}

/*
 * Call this function to write TS header and adoption field to buffer
 */
int32_t S3_HLS_TS_Write_To_Buffer(S3_HLS_BUFFER_CTX* ctx) {
    uint32_t ret = 0;
    uint32_t pid = ts_header[S3_HLS_TS_PID_HIGH_POS] & 0x1F;
    pid *= 256;
    pid += ts_header[S3_HLS_TS_PID_LOW_POS];
    
    ts_header[S3_HLS_TS_COUNTER_INDEX] &= 0xF0;
    switch(pid) {
        case S3_HLS_Video_PID:
            ts_header[S3_HLS_TS_COUNTER_INDEX] |= (m_ts_video_counter & 0x0F);
            break;
        case S3_HLS_Audio_PID:
            ts_header[S3_HLS_TS_COUNTER_INDEX] |= (m_ts_audio_counter & 0x0F);
            break;
    }

    // write to buffer
    uint8_t* first_part_start = ts_header;
    uint32_t first_part_length = 4;
    
    uint8_t* second_part_start = NULL;
    uint32_t second_part_length = 0;
    
    if(ts_header[S3_HLS_TS_ADOPTION_FLAG_POS] & S3_HLS_TS_ADOPTION_FLAG) { // do have adoption field
        first_part_length++; // adoption length field
        if(ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS] > 0) {
            if(ts_header[S3_HLS_TS_PCR_FLAG_POS] & S3_HLS_TS_PCR_FLAG) {
                first_part_length += 7; // adoption flags 1 + pcr 6
            } else {
                first_part_length += 1; // adoption flags 1
            }
        }
        
        if(ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS] > first_part_length - 5) {
            // need to fill remaining fields
            second_part_start = const_fill_word;
            second_part_length = ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS] - (first_part_length - 5);
        }
    } 

    ret = S3_HLS_Put_To_Buffer(ctx, first_part_start, first_part_length);
    if(0 > ret)
        return ret;
    
    int32_t length = ret;
    ret = S3_HLS_Put_To_Buffer(ctx, second_part_start, second_part_length);
    if(0 > ret)
        return ret;
        
    length += ret;
    
    S3_HLS_TS_Reset_Header_Info();
    
    switch(pid) {
        case S3_HLS_Video_PID:
            m_ts_video_counter++;
            break;
        case S3_HLS_Audio_PID:
            m_ts_audio_counter++;
            break;
    }
    
    return  length;
}

/*
 * Call this function to set pid before write TS Header to buffer
 */
void S3_HLS_TS_Set_Pid(uint32_t pid) {
    ts_header[S3_HLS_TS_PID_HIGH_POS] |= (pid & S3_HLS_TS_PID_HEX_CODE) >> 8;
    ts_header[S3_HLS_TS_PID_LOW_POS] = (pid & 0xFF);
}

/*
 * Call this function to set payload start flag before write TS Header to buffer
 */
void S3_HLS_TS_Set_Payload_Start() {
    ts_header[S3_HLS_TS_PAYLOAD_START_POS] |= S3_HLS_TS_PAYLOAD_START_FLAG;
}

/*
 * Call this function to set random access flag before write TS Header to buffer
 */
void S3_HLS_TS_Set_Random_Access() {
    ts_header[S3_HLS_TS_ADOPTION_FLAG_POS] |= S3_HLS_TS_ADOPTION_FLAG; // random access need adoption part
    ts_header[S3_HLS_TS_RANDOM_ACCESS_FLAG_POS] |= S3_HLS_TS_RANDOM_ACCESS_FLAG;
    
    if(ts_header[S3_HLS_TS_PCR_FLAG_POS] & S3_HLS_TS_PCR_FLAG) {
        // also contains pcr
        ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS] = 7;
    } else {
        // no pcr
        ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS] = 1;
    }
}

/*
 * Call this function to set PCR flag and value before write TS Header to buffer
 */
void S3_HLS_TS_Set_PCR(uint64_t input_timestamp) {
    ts_header[S3_HLS_TS_ADOPTION_FLAG_POS] |= S3_HLS_TS_ADOPTION_FLAG;
    ts_header[S3_HLS_TS_PCR_FLAG_POS] |= S3_HLS_TS_PCR_FLAG;
    
    ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS] = 7;
    
    uint64_t timestamp = input_timestamp / 100 * 9; // convert nanosecond based timestamp to 90K signal
    
    ts_header[S3_HLS_PCR_START_POS] = ((timestamp >> 25) & 0xFF);
    ts_header[S3_HLS_PCR_START_POS + 1] = ((timestamp >> 17) & 0xFF);
    ts_header[S3_HLS_PCR_START_POS + 2] = ((timestamp >> 9) & 0xFF);
    ts_header[S3_HLS_PCR_START_POS + 3] = ((timestamp >> 1) & 0xFF);
    ts_header[S3_HLS_PCR_START_POS + 4] = (timestamp << 7) | 0x7E;
    ts_header[S3_HLS_PCR_START_POS + 5] = 0;
}

/*
 * Call this function to fill adoption fields if data_length is less than remaining bytes. 
 * Call this function before write TS Header to buffer and after set random access and pcr
 */
void S3_HLS_TS_Fill_Remaining_Length(uint32_t data_length) {
    TS_DEBUG("Input Data Length:%d\n", data_length);
    uint8_t length = 4; // base length
    if(ts_header[S3_HLS_TS_ADOPTION_FLAG_POS] & S3_HLS_TS_ADOPTION_FLAG) {
        TS_DEBUG("Has Adoption\n");
        length ++; // do have adoption length field
    }
    
    if(ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS] > 0) {
        TS_DEBUG("Adoption Length: %d\n", ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS]);
        length += ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS]; // do have adoption length
    }
    
    TS_DEBUG("Data + Header Length: %d\n", length + data_length);
    if(S3_HLS_TS_PACKET_SIZE > length + data_length) {
        // need to fill some part
        uint8_t gap = S3_HLS_TS_PACKET_SIZE - length - data_length;
        if(ts_header[S3_HLS_TS_ADOPTION_FLAG_POS] & S3_HLS_TS_ADOPTION_FLAG) {
            // already contains an adoption length field
            ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS] += gap;
        } else {
            // need add an adoption length
            gap--; // due to need add adoption length so minus 1
            ts_header[S3_HLS_TS_ADOPTION_FLAG_POS] |= S3_HLS_TS_ADOPTION_FLAG;
            ts_header[S3_HLS_TS_ADOPTION_LENGTH_POS] = gap;
            if(gap > 0) {
                ts_header[S3_HLS_TS_RANDOM_ACCESS_FLAG_POS] = 0; // mark as no flags
            }
        }
    }
}

/*
 * Call this function to reset the counter field in ts header
 * need to think about mapping for different PID
 */
void S3_HLS_TS_Reset_Counter(uint32_t pid) {
    switch(pid) {
        case S3_HLS_Video_PID:
            m_ts_video_counter = 0;
            break;
        case S3_HLS_Audio_PID:
            m_ts_audio_counter = 0;
            break;
    }
}