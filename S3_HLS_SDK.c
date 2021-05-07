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

#include <unistd.h>

#include "S3_HLS_SDK.h"
#include "stdlib.h"
#include "math.h"
#include "pthread.h"
#include "string.h"
#include "stdio.h"
#include "S3_Simple_Put.h"

//#define DEBUG_HLS
#ifdef DEBUG_HLS
#define DEBUG_PRINT(x, ...) printf(x, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

#define PCR_START_TIMESTAMP		63000
#define PTS_START_TIMESTAMP		126000
#define PCR_PTS_DEFAULT_INTERVAL	3000

#define S3_HLS_H264_NALU_BITS		0x1F
#define S3_HLS_NALU_BYTE_POS		5

// ping pong buffer control
static unsigned char* m_ping_buffer = NULL;
static unsigned char* m_pong_buffer = NULL;
static unsigned char* m_ping_cur = NULL;
static unsigned char* m_pong_cur = NULL;

// pointer for active buffer partition
#define ACTIVE_BUFFER_NONE		0
#define ACTIVE_BUFFER_PING		1
#define ACTIVE_BUFFER_PONG		2
static unsigned char  m_active_buffer = ACTIVE_BUFFER_NONE;

// buffer size
static unsigned int   m_size = 0;

static pthread_mutex_t m_lock;

// non-image buffer control
static unsigned char* m_non_image_start = NULL;

// pcr and pts timestamps
static unsigned long long m_pcr_timestamp = PCR_START_TIMESTAMP;
static unsigned long long m_pts_timestamp = PTS_START_TIMESTAMP;

// max timestamp value for pcr & pts. beyond this value will ignore the high bits and only leave the lower bits
static unsigned long long m_timestamp_max = 0; //pow(2, 33);
static unsigned long long m_timestamp_interval = PCR_PTS_DEFAULT_INTERVAL;

// ts packet counter fields
static unsigned char m_pmt_ts_counter = 0;
static unsigned char m_pat_ts_counter = 0;
static unsigned char m_video_ts_counter = 0;

// default segment frame
static S3_HLS_H264E_NALU_TYPE_E m_segment_type = S3_HLS_H264E_NALU_SPS;

// default frame 
static unsigned char m_segment_interval = 3; // 3 segment frames for each file
static unsigned char m_pcr_interval = 2; // 2 frames for each pcr
static unsigned char m_pat_interval = 3; // 3 frames for each pat/pmt

// counter used for packet segment and add pcr, pat frames
static unsigned char m_segment_cnt = 0;
static unsigned char m_pcr_cnt = 0;
static unsigned char m_pat_cnt = 0;

// used in pat/pmt packets
const unsigned int crcTable[256] = {
0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
 };

unsigned int S3_HLS_CRC_Calculate(unsigned char *buffer, unsigned int size){
    unsigned int crc = 0xFFFFFFFF;
    if(NULL == buffer) {
        return crc;
    }

    unsigned char* end = buffer + size;
    while(buffer < end) {
        crc = (crc << 8) ^ crcTable[((crc >> 24) ^ *buffer) & 0xFF];
        buffer++;
    }

    return crc;
}

S3_HLS_H264E_NALU_TYPE_E S3_HLS_Get_H264E_Frame_Type(unsigned char* frame_data, unsigned int frame_length) {
    if(S3_HLS_NALU_BYTE_POS > frame_length) {
        return S3_HLS_H264E_NALU_UNSPECIFIED;
    }
    
    if(0x00 == frame_data[0] && 0x00 == frame_data[1] && 0x00 == frame_data[2] && 0x01 == frame_data[3]) {
        return (S3_HLS_H264E_NALU_TYPE_E)(frame_data[4] & S3_HLS_H264_NALU_BITS);
    }

    return S3_HLS_H264E_NALU_UNSPECIFIED;
}

int S3_HLS_Initialize(unsigned int buffer_size) {
    DEBUG_PRINT("S3_HLS_Initialize\n");
    m_timestamp_max = pow(2,33);
    m_ping_buffer = (unsigned char*) malloc (buffer_size);
    if(NULL == m_ping_buffer) {
        return S3_HLS_NOT_ENOUGH_MEMORY;
    }
    
    m_size = buffer_size/2;
    m_pong_buffer = m_ping_buffer + m_size;
    
    m_non_image_start = NULL;
    m_active_buffer = ACTIVE_BUFFER_PING;
    
    m_ping_cur = m_ping_buffer;
    m_pong_cur = m_pong_buffer;
    
    pthread_mutex_init(&m_lock, NULL);
    
    return S3_HLS_OK;
}

// Free resources especially for pingpong buffer when finalize
void S3_HLS_Finalize() {
    DEBUG_PRINT("S3_HLS_Finalize\n");
    if(NULL != m_ping_buffer) {
        free(m_ping_buffer);
        m_ping_buffer = NULL;
    }
}

// Use FPS to calculate PCR, PTS, DTS, common FPS are 25, 30 etc.
// This operation never fail so return void
void S3_HLS_Set_FPS(unsigned char fps) {
    DEBUG_PRINT("S3_HLS_Set_FPS\n");
    m_timestamp_interval = 90000/fps;
}

// Use frame_type as Segmentation start and trigger segment of stream
void S3_HLS_Set_Segmentation_Frame(S3_HLS_H264E_NALU_TYPE_E frame_type) {
    DEBUG_PRINT("S3_HLS_Set_Segmentation_Frame\n");
    m_segment_type = frame_type;
}

// Max Segmentation frames in a single segment, will trigger segment when counter is greater than or equal to this count
void S3_HLS_Set_Segmentation_Frame_Count(unsigned char frame_count) {
    DEBUG_PRINT("S3_HLS_Set_Segmentation_Frame_Count\n");
    m_segment_interval = frame_count;
}

int S3_HLS_Write_TS_Header(unsigned char* buffer, unsigned int buffer_size, unsigned char payload_start, unsigned int pid, unsigned char adoption_field) {
    DEBUG_PRINT("S3_HLS_Write_TS_Header\n");
    
    if(buffer_size < 4)
        return 0;
        
    unsigned char counter;
    switch(pid) {
        case S3_HLS_PAT_PID:
            counter = m_pat_ts_counter;
            m_pat_ts_counter++;
            break;
        case S3_HLS_VIDEO_PID:
            counter = m_video_ts_counter;
            m_video_ts_counter++;
            break;
        case S3_HLS_PMT_PID:
            counter = m_pmt_ts_counter;
            m_pmt_ts_counter++;
            break;
        default:
            return S3_HLS_INVALID_PID;
    }

    *buffer++ = 0x47; // byte 0
    *buffer = (payload_start ? 0x40 : 0x00); // byte 1
    *buffer++ |= ((pid >> 8) & 0x1F);
    *buffer++ = (pid & 0xFF); // byte 2
    
    *buffer++ = (adoption_field ? 0x30 : 0x10) | (counter & 0x0F); // byte 3
    
    return 4;
}

// payload_length is used to calculate whether need adoption fields to fill with 0xff
int S3_HLS_Write_TS_Adoption_Fields(unsigned char* buffer, unsigned int buffer_size, unsigned char random_access, unsigned char has_pcr, unsigned int payload_length) {
    DEBUG_PRINT("S3_HLS_Write_TS_Header\n");
    unsigned char target_length = 1; // for adoption length
    if(has_pcr || random_access)
        target_length += 1; // for adoption flags
    
    if(has_pcr)
        target_length += 6;
    
    if(payload_length < S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH - target_length)
        target_length += S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH - target_length - payload_length;
        
    if(buffer_size < target_length)
        return 0;
    
    //printf("target_length: %d, %d\n", target_length, payload_length);
    // start write
    unsigned char ret = target_length;
    *buffer++ = (--target_length); // byte 0 for adoption field byte 5 for ts header, adoption field length not include length it self
    if(target_length > 0) {
        *buffer = 0; // byte 1 for adoption field byte 6 for ts header, adoption flags if any
        if(random_access)
            *buffer |= 0x40;
            
        if(has_pcr)
            *buffer |= 0x10;
            
        buffer++;
        target_length--;

        if(has_pcr) {
            *buffer++ = m_pcr_timestamp >> 25;
            *buffer++ = m_pcr_timestamp >> 17;
            *buffer++ = m_pcr_timestamp >> 9;
            *buffer++ = m_pcr_timestamp >> 1;
            *buffer++ = m_pcr_timestamp << 7 | 0x7E;
            *buffer++ = 0;
            
            target_length -= 6;
        }
    }
    
    while(target_length--) {
        *buffer++ = 0xFF;
    }
    
    return ret;
}

int S3_HLS_Write_Pes_Header(unsigned char* buffer, unsigned int buffer_size) {
    DEBUG_PRINT("S3_HLS_Write_Pes_Header\n");

    if(S3_HLS_PES_HEADER_LENGTH > buffer_size)
        return 0;
        
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
    
    *buffer++ = 0;
    *buffer++ = 0;
    *buffer++ = 0;
    *buffer++ = 1;

    *buffer++ = 0x09;
    *buffer++ = 0xf0;
    
    return S3_HLS_PES_HEADER_LENGTH;
}

int S3_HLS_Write_Pat(unsigned char* buffer, unsigned int buffer_size) {
    DEBUG_PRINT("S3_HLS_Write_Pat\n");

    if(buffer_size < S3_HLS_TS_PACKET_LENGTH)
        return 0;
    
    unsigned char bytes_written = S3_HLS_Write_TS_Header(buffer, buffer_size, /* payload start */1, S3_HLS_PAT_PID, 0);
    if(0 >= bytes_written)
        return bytes_written;

    buffer += bytes_written;
    memset(buffer, 0xff, S3_HLS_TS_PACKET_LENGTH - bytes_written);

    *buffer++ = 0x00;
    
    // pat table id
    unsigned char* start = buffer;
    *buffer++ = 0x00;
    
    *buffer++ = 0xb0;
    *buffer++ = 0x0d;
    
    *buffer++ = 0x00;
    *buffer++ = 0x01;
    
    *buffer++ = 0xc1;
    *buffer++ = 0x00;
    *buffer++ = 0x00;
    
    *buffer++ = 0x00;
    *buffer++ = 0x01;
    
    *buffer++ = 0xf0 | (S3_HLS_PAT_PID >> 8);
    *buffer++ = S3_HLS_PAT_PID & 0xff;
    
    unsigned int crc32_res = S3_HLS_CRC_Calculate(start, buffer - start);
    *buffer++ = crc32_res >> 24;
    *buffer++ = (crc32_res >> 16) & 0xff;
    *buffer++ = (crc32_res >> 8) & 0xff;
    *buffer++ = crc32_res & 0xff;
    
    return S3_HLS_TS_PACKET_LENGTH;
}

int S3_HLS_Write_Pmt(unsigned char* buffer, unsigned int buffer_size) {
    DEBUG_PRINT("S3_HLS_Write_Pmt\n");

    if(buffer_size < S3_HLS_TS_PACKET_LENGTH)
        return 0;
    
    unsigned char bytes_written = S3_HLS_Write_TS_Header(buffer, buffer_size, /* payload start */1, S3_HLS_PMT_PID, 0);
    if(0 >= bytes_written)
        return bytes_written;

    buffer += bytes_written;
    memset(buffer, 0xff, S3_HLS_TS_PACKET_LENGTH - bytes_written);

    *buffer++ = 0x00;
    
    // pat table id
    unsigned char* start = buffer;
    *buffer++ = 0x02;
    
    *buffer++ = 0xb0;
    *buffer++ = 0x12;
    
    *buffer++ = 0x00;
    *buffer++ = 0x01;
    
    *buffer++ = 0xc1;
    *buffer++ = 0x00;
    *buffer++ = 0x00;
    
    *buffer++ = 0xe1;
    *buffer++ = 0x00;
    
    *buffer++ = 0xf0;
    *buffer++ = 0x00;
    
    *buffer++ = 0x1b;

    *buffer++ = 0xe0 | ((S3_HLS_VIDEO_PID >> 8) & 0xff);
    *buffer++ = S3_HLS_VIDEO_PID & 0xff;

    *buffer++ = 0xf0;
    *buffer++ = 0x00;

    unsigned int crc32_res = S3_HLS_CRC_Calculate(start, buffer - start);
    *buffer++ = crc32_res >> 24;
    *buffer++ = (crc32_res >> 16) & 0xff;
    *buffer++ = (crc32_res >> 8) & 0xff;
    *buffer++ = crc32_res & 0xff;
    
    return S3_HLS_TS_PACKET_LENGTH;
}

void S3_HLS_Reset_Counter() {
    DEBUG_PRINT("S3_HLS_Reset_Counter\n");

    m_pcr_timestamp = 63000;
    m_pts_timestamp = 126000;
    
    m_segment_cnt = 0;
    m_pcr_cnt = 0;
    m_pat_cnt = 0;

    m_pmt_ts_counter = 0;
    m_pat_ts_counter = 0;
    m_video_ts_counter = 0;
}

int S3_HLS_Move_Non_Image_Buffer(unsigned char* target, unsigned int buffer_size, unsigned char* source, unsigned int size) {
    DEBUG_PRINT("S3_HLS_Move_Non_Image_Buffer\n");

    if(target - source > buffer_size)
        return 0;

    unsigned int cur = size;    
    while(cur) {
        --cur;
        *(target + cur) = *(source + cur);
    }
    
    return size;
}

int S3_HLS_Put_Pes_Frame(unsigned char* frame_addr, unsigned int frame_length) {
    DEBUG_PRINT("S3_HLS_Put_Pes_Frame\n");

    unsigned char* buffer_start = NULL;
    unsigned char* buffer_cur = NULL;
    unsigned char* buffer_frame_start = NULL;
    unsigned char* buffer_non_img_start = NULL;
    
    int ret = 0;

    if (0 != pthread_mutex_lock(&m_lock)) // lock failed
        return S3_HLS_LOCK_FAILED;
    
    switch(m_active_buffer) {
        case ACTIVE_BUFFER_NONE:
            pthread_mutex_unlock(&m_lock);
            return S3_HLS_NOT_ENOUGH_MEMORY;
        case ACTIVE_BUFFER_PING:
            buffer_start = m_ping_buffer;
            buffer_cur = m_ping_cur;
            break;
        case ACTIVE_BUFFER_PONG:
            buffer_start = m_pong_buffer;
            buffer_cur = m_pong_cur;
            break;
    }
    buffer_non_img_start = m_non_image_start;

    pthread_mutex_unlock(&m_lock);
    
    buffer_frame_start = buffer_non_img_start ? buffer_non_img_start : buffer_cur;
    
    S3_HLS_H264E_NALU_TYPE_E frame_type = S3_HLS_Get_H264E_Frame_Type(frame_addr, frame_length);
    
    unsigned char random_access = frame_type == S3_HLS_H264E_NALU_IDR;
    
    // complex calculation on first packet, from second packet will be much simplier
    unsigned int move_behind = 0;
    unsigned int buffer_size = 0;
    if (NULL != buffer_non_img_start) { // have non-image info in buffer
        // calculate pat and pmt size
        buffer_size = buffer_cur - buffer_non_img_start;
        move_behind = 0;
        if(0 == m_pat_cnt) { // may need to have space for pat and pmt
            move_behind += S3_HLS_TS_PACKET_LENGTH;
            move_behind += S3_HLS_TS_PACKET_LENGTH;
        }
        
        // calculate ts header and adoption field length
        move_behind += S3_HLS_TS_HEADER_LENGTH;

        unsigned int adoption_length = (random_access || m_pcr_cnt == 0 ? 2 : 0); // adoption flag field plus adoption length field
        if(0 == m_pcr_cnt) // adoption field length
            adoption_length += 6;
            
        // calculate additional adoption field length if buffer + frame cannot fill 1 ts packet
        if(S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH - adoption_length - S3_HLS_PES_HEADER_LENGTH > buffer_size + frame_length)
            adoption_length += S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH - adoption_length  - S3_HLS_PES_HEADER_LENGTH - buffer_size - frame_length;
        
        move_behind += adoption_length;
        move_behind += S3_HLS_PES_HEADER_LENGTH;
        
        // move buffer to correct position
        buffer_cur = buffer_non_img_start;

        ret = S3_HLS_Move_Non_Image_Buffer(buffer_cur + move_behind, m_size - (buffer_cur + move_behind - buffer_start), buffer_cur, buffer_size);
        if(0 >= ret)
            return ret;
        
        // start write 
        if(0 == m_pat_cnt) { // write pat and pmt if necessary
            ret = S3_HLS_Write_Pat(buffer_cur, m_size - (buffer_cur - buffer_start));
            if(0 >= ret)
                return ret;
                
            buffer_cur += ret;
            
            ret = S3_HLS_Write_Pmt(buffer_cur, m_size - (buffer_cur - buffer_start));
            if(0 >= ret)
                return ret;

            buffer_cur += ret;
        }
        
        // start write pes
        unsigned char* ts_start_pos = buffer_cur; // mark ts packet start location
        ret = S3_HLS_Write_TS_Header(buffer_cur, m_size - (buffer_cur - buffer_start), 1, S3_HLS_VIDEO_PID, random_access || m_pcr_cnt == 0 || buffer_size + frame_length < S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH - adoption_length);
        if(0 >= ret)
            return ret;
        
        // write adoption field
        buffer_cur += ret;
        if(0 != adoption_length) {
            ret = S3_HLS_Write_TS_Adoption_Fields(buffer_cur, m_size - (buffer_cur - buffer_start), random_access, m_pat_cnt == 0, buffer_size + frame_length);
            if(0 >= ret)
                return ret;
            
            buffer_cur += ret;
        }

        ret = S3_HLS_Write_Pes_Header(buffer_cur, m_size - (buffer_cur - buffer_start));
        if(0 >= ret)
            return ret;

        buffer_cur += ret; // actual buffer start position，buffer ends at buffer_cur + buffer_size

        // buffer already in place
        while (buffer_cur + buffer_size > ts_start_pos + S3_HLS_TS_PACKET_LENGTH) { // more buffer need to move
            ts_start_pos += S3_HLS_TS_PACKET_LENGTH; // next ts start location
            buffer_size =  buffer_cur + buffer_size - ts_start_pos - S3_HLS_TS_PACKET_LENGTH; // remaining buffer

            move_behind = S3_HLS_TS_HEADER_LENGTH;
            adoption_length = 0;
            if(buffer_size + frame_length < S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH) // buffer plus frame size and see if need adoption field
                adoption_length = S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH - buffer_size - frame_length;
                
            move_behind += adoption_length;

            ret = S3_HLS_Move_Non_Image_Buffer(ts_start_pos + S3_HLS_TS_HEADER_LENGTH, m_size - (ts_start_pos + S3_HLS_TS_HEADER_LENGTH - buffer_start), ts_start_pos, buffer_size);
            if(0 >= ret)
                return ret;
            
            ret = S3_HLS_Write_TS_Header(buffer_cur, m_size - (buffer_cur - buffer_start), 0, S3_HLS_VIDEO_PID, 0);
            if(0 >= ret)
                return ret;
                
            buffer_cur += ret;

            if(0 != adoption_length) {
                ret = S3_HLS_Write_TS_Adoption_Fields(buffer_cur, m_size - (buffer_cur - buffer_start), 0, 0, buffer_size + frame_length);
                if(0 >= ret)
                    return ret;
                    
                buffer_cur += ret;
            }
        }
        
        // fill packet with frame
        if(buffer_cur + buffer_size < ts_start_pos + S3_HLS_TS_PACKET_LENGTH) { // fill gap with frame data
            buffer_cur = buffer_cur + buffer_size;
            buffer_size = ts_start_pos + S3_HLS_TS_PACKET_LENGTH - buffer_cur;

            memcpy(buffer_cur, frame_addr, buffer_size);
            frame_addr += buffer_size;
            frame_length -= buffer_size;
        }

        // prepare for write frames
        while(frame_length) {
            ts_start_pos += S3_HLS_TS_PACKET_LENGTH;
            
            ret = S3_HLS_Write_TS_Header(ts_start_pos, m_size - (ts_start_pos - buffer_start), 0, S3_HLS_VIDEO_PID, (frame_length < S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH));
            if(0 >= ret)
                return ret;
            
            adoption_length = 0;
            if(frame_length < S3_HLS_TS_PACKET_LENGTH - ret) 
                adoption_length = S3_HLS_Write_TS_Adoption_Fields(ts_start_pos + ret, m_size - (ts_start_pos + ret - buffer_start), 0, 0, frame_length);

            memcpy(ts_start_pos + ret + adoption_length, frame_addr, S3_HLS_TS_PACKET_LENGTH - ret - adoption_length);
            
            frame_addr += S3_HLS_TS_PACKET_LENGTH - ret - adoption_length;
            frame_length -= S3_HLS_TS_PACKET_LENGTH - ret - adoption_length;
        }
        
        ts_start_pos += S3_HLS_TS_PACKET_LENGTH;

        // clean non-image buffer info at last
        if (0 != pthread_mutex_lock(&m_lock)) // lock failed
            return S3_HLS_LOCK_FAILED;
    
        switch(m_active_buffer) {
            case ACTIVE_BUFFER_NONE:
                pthread_mutex_unlock(&m_lock);
                return S3_HLS_NOT_ENOUGH_MEMORY;
            case ACTIVE_BUFFER_PING:
                m_ping_cur = ts_start_pos;
                break;
            case ACTIVE_BUFFER_PONG:
                m_pong_cur = ts_start_pos;
                break;
        }
        
        m_non_image_start = NULL;

        pthread_mutex_unlock(&m_lock);
    } else {
        if(0 == m_pat_cnt) {
            ret = S3_HLS_Write_Pat(buffer_cur, m_size - (buffer_cur - buffer_start));
            if(0 >= ret)
                return ret;
                
            buffer_cur += ret;
            
            ret = S3_HLS_Write_Pmt(buffer_cur, m_size - (buffer_cur - buffer_start));
            if(0 >= ret)
                return ret;

            buffer_cur += ret;
        }
        
        unsigned char* ts_start_pos = buffer_cur;
        ret = S3_HLS_Write_TS_Header(buffer_cur, m_size - (buffer_cur - buffer_start), 1, S3_HLS_VIDEO_PID, random_access || m_pcr_cnt == 0 || frame_length < S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH - (random_access || m_pcr_cnt == 0 ? 2 : 0) - (m_pcr_cnt == 0 ? 6 : 0) - S3_HLS_PES_HEADER_LENGTH);
        if(0 >= ret)
            return ret;
        
        buffer_cur += ret;
        
        if(random_access || m_pcr_cnt == 0 || frame_length < S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH - (random_access || m_pcr_cnt == 0 ? 2 : 0) - (m_pcr_cnt == 0 ? 6 : 0) - S3_HLS_PES_HEADER_LENGTH) {
            ret = S3_HLS_Write_TS_Adoption_Fields(buffer_cur, m_size - (buffer_cur - buffer_start), random_access, m_pat_cnt == 0, frame_length + S3_HLS_PES_HEADER_LENGTH);
            if(0 >= ret)
                return ret;
            
            buffer_cur += ret;
        }
        
        ret = S3_HLS_Write_Pes_Header(buffer_cur, m_size - (buffer_cur - buffer_start));
        if(0 >= ret)
            return ret;

        buffer_cur += ret;

        // copy data
        memcpy(buffer_cur, frame_addr, S3_HLS_TS_PACKET_LENGTH - (buffer_cur - ts_start_pos));
        frame_length -= S3_HLS_TS_PACKET_LENGTH - (buffer_cur - ts_start_pos);
        frame_addr += S3_HLS_TS_PACKET_LENGTH - (buffer_cur - ts_start_pos);

        buffer_cur += S3_HLS_TS_PACKET_LENGTH - (buffer_cur - ts_start_pos);

        while(frame_length) {
            ts_start_pos = buffer_cur;
            ret = S3_HLS_Write_TS_Header(buffer_cur, m_size - (buffer_cur - buffer_start), 0, S3_HLS_VIDEO_PID, (frame_length < S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH));
            if(0 >= ret)
                return ret;
                
            buffer_cur += ret;
            
            if(frame_length < S3_HLS_TS_PACKET_LENGTH - S3_HLS_TS_HEADER_LENGTH) {
                ret = S3_HLS_Write_TS_Adoption_Fields(buffer_cur, m_size - (buffer_cur - buffer_start), 0, 0, frame_length);
                if(0 >= ret)
                    return ret;
                    
                buffer_cur += ret;
            }
            
            memcpy(buffer_cur, frame_addr, S3_HLS_TS_PACKET_LENGTH - (buffer_cur - ts_start_pos));
            
            frame_addr += S3_HLS_TS_PACKET_LENGTH - (buffer_cur - ts_start_pos);
            frame_length -= S3_HLS_TS_PACKET_LENGTH - (buffer_cur - ts_start_pos);

            buffer_cur += S3_HLS_TS_PACKET_LENGTH - (buffer_cur - ts_start_pos);
        }

        if (0 != pthread_mutex_lock(&m_lock)) // lock failed
            return S3_HLS_LOCK_FAILED;
    
        switch(m_active_buffer) {
            case ACTIVE_BUFFER_NONE:
                pthread_mutex_unlock(&m_lock);
                return S3_HLS_NOT_ENOUGH_MEMORY;
            case ACTIVE_BUFFER_PING:
                m_ping_cur = buffer_cur;
                break;
            case ACTIVE_BUFFER_PONG:
                m_pong_cur = buffer_cur;
                break;
        }

        pthread_mutex_unlock(&m_lock);
    }
    
    
    m_pat_cnt++;
    if(m_pat_cnt == m_pat_interval)
        m_pat_cnt = 0;

    m_pcr_cnt++;
    if(m_pcr_cnt == m_pcr_interval)
        m_pcr_cnt = 0;
        
    m_pcr_timestamp += m_timestamp_interval;
    m_pcr_timestamp %= m_timestamp_max;
    m_pts_timestamp += m_timestamp_interval;
    m_pts_timestamp %= m_timestamp_max;
    
    return buffer_cur - buffer_frame_start;
}

int S3_HLS_Put_Buffer(unsigned char* frame_addr, unsigned int frame_length) {
    DEBUG_PRINT("S3_HLS_Put_Buffer\n");

    unsigned char* buffer_start = NULL;
    unsigned char* buffer_cur = NULL;
    unsigned char* buffer_non_img_start = NULL;

    if (0 != pthread_mutex_lock(&m_lock)) // lock failed
        return S3_HLS_LOCK_FAILED;
        
    switch(m_active_buffer) {
        case ACTIVE_BUFFER_NONE:
            pthread_mutex_unlock(&m_lock);
            return S3_HLS_NOT_ENOUGH_MEMORY;
        case ACTIVE_BUFFER_PING:
            buffer_start = m_ping_buffer;
            buffer_cur = m_ping_cur;
            break;
        case ACTIVE_BUFFER_PONG:
            buffer_start = m_pong_buffer;
            buffer_cur = m_pong_cur;
            break;
    }

    pthread_mutex_unlock(&m_lock);
    
    if(frame_length > m_size - (buffer_cur - buffer_start))
        return 0;

    buffer_non_img_start = buffer_cur;
    memcpy(buffer_cur, frame_addr, frame_length);
    buffer_cur += frame_length;

    if (0 != pthread_mutex_lock(&m_lock)) // lock failed
        return S3_HLS_LOCK_FAILED;
    
    switch(m_active_buffer) {
        case ACTIVE_BUFFER_PING:
            m_ping_cur = buffer_cur;
            break;
        case ACTIVE_BUFFER_PONG:
            m_pong_cur = buffer_cur;
            break;
    }
    
    if(NULL == m_non_image_start)
        m_non_image_start = buffer_non_img_start;
    
    pthread_mutex_unlock(&m_lock);
    
    return frame_length;
}

// Put video frame to buffer and may trigger auto commit
int S3_HLS_Put_Frame(unsigned char* frame_addr, unsigned int frame_length) {
    DEBUG_PRINT("S3_HLS_Put_Frame\n");

    S3_HLS_H264E_NALU_TYPE_E frame_type = S3_HLS_Get_H264E_Frame_Type(frame_addr, frame_length);
    if(m_segment_type == frame_type) {
        // segment frame, verify counter switch partition if match
        if(m_segment_cnt == m_segment_interval) {
            S3_HLS_Reset_Counter();
            // switch partition lock before modify patition parameters
            if (0 != pthread_mutex_lock(&m_lock)) // lock failed
                return S3_HLS_LOCK_FAILED;

            // switch buffer
            switch(m_active_buffer) {
                case ACTIVE_BUFFER_NONE:
                    if(m_ping_buffer == m_ping_cur)
                        m_active_buffer = ACTIVE_BUFFER_PING;
                    else if(m_pong_buffer == m_pong_cur)
                        m_active_buffer = ACTIVE_BUFFER_PONG;
                    break;
                case ACTIVE_BUFFER_PING: // using ping
                    if(m_pong_cur == m_pong_buffer)
                        m_active_buffer = ACTIVE_BUFFER_PONG;
                    else
                        m_active_buffer = ACTIVE_BUFFER_NONE; // buffer full
                    break;
                case ACTIVE_BUFFER_PONG: // using pong
                    if(m_ping_cur == m_ping_buffer)
                        m_active_buffer = ACTIVE_BUFFER_PING;
                    else
                        m_active_buffer = ACTIVE_BUFFER_NONE; // buffer full
                    break;
            }
            
            pthread_mutex_unlock(&m_lock);
        }
        // increase segment counter
        m_segment_cnt ++;
    }
    
    switch(frame_type) {
        case S3_HLS_H264E_NALU_NON_IDR:
        case S3_HLS_H264E_NALU_DPA:
        case S3_HLS_H264E_NALU_DPB:
        case S3_HLS_H264E_NALU_DPC:
        case S3_HLS_H264E_NALU_IDR:
            return S3_HLS_Put_Pes_Frame(frame_addr, frame_length);
        default:
            return S3_HLS_Put_Buffer(frame_addr, frame_length);
    }
}

void S3_HLS_Write_To_S3() {
    DEBUG_PRINT("S3_HLS_Write_To_S3\n");

    unsigned char* buffer_start = NULL;
    unsigned char* buffer_cur = NULL;
    
    if (0 != pthread_mutex_lock(&m_lock)) // lock failed
        return;

    // switch buffer
    switch(m_active_buffer) {
        case ACTIVE_BUFFER_NONE:
            if(m_ping_buffer != m_ping_cur) {
                buffer_start = m_ping_buffer;
                buffer_cur = m_ping_cur;
            }
            else if(m_pong_buffer != m_pong_cur) {
                buffer_start = m_pong_buffer;
                buffer_cur = m_pong_cur;
            }
            break;
        case ACTIVE_BUFFER_PING: // using ping
            if(m_pong_cur != m_pong_buffer) {
                buffer_start = m_pong_buffer;
                buffer_cur = m_pong_cur;
            }
            break;
        case ACTIVE_BUFFER_PONG: // using pong
            if(m_ping_cur != m_ping_buffer) {
                buffer_start = m_ping_buffer;
                buffer_cur = m_ping_cur;
            }
            break;
    }
    
    pthread_mutex_unlock(&m_lock);
    
    if(NULL == buffer_start) {
        usleep(50*1000);
        return;
    }

    DEBUG_PRINT("Writing To S3!\n");
    time_t rawtime;
    time(&rawtime);
    struct tm* tm = gmtime( &rawtime );

    int size = snprintf(NULL, 0, S3_HLS_KEY_FORMAT, tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    char* file_name = (char*)malloc(size + 1);
    if(NULL == file_name)
        return;
        
    if(0 >= snprintf(file_name, size + 1, S3_HLS_KEY_FORMAT, tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec)) {
        free(file_name);
        return;
    }

    DEBUG_PRINT("file_name: %s\n", file_name);

    S3_Put_Object(file_name, buffer_start, buffer_cur - buffer_start);

    if (0 != pthread_mutex_lock(&m_lock)) // lock failed
        return;

    if(buffer_start == m_ping_buffer)
        m_ping_cur = m_ping_buffer;
    else if (buffer_start == m_pong_buffer)
        m_pong_cur = m_pong_buffer;
        
    pthread_mutex_unlock(&m_lock);

    usleep(50*1000);
}

