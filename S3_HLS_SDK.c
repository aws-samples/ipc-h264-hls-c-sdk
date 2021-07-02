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
#include <semaphore.h>

#include "curl/curl.h"

#include "S3_HLS_SDK.h"
#include "S3_HLS_Return_Code.h" 
#include "S3_HLS_Buffer_Mgr.h"
#include "S3_HLS_Pes.h"
#include "S3_HLS_Upload_Thread.h"
#include "S3_HLS_S3_Put_Client.h"
#include "S3_HLS_Queue.h"

#define S3_HLS_TS_OBJECT_KEY_FORMAT "%s/%04d/%02d/%02d/%02d/%02d/%02d.ts"

#define S3_HLS_SDK_EMPTY_STRING ""

#define S3_HLS_SDK_DEBUG

#ifdef S3_HLS_SDK_DEBUG
#define SDK_DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define SDK_DEBUG(x, ...)
#endif

static S3_HLS_QUEUE_CTX*  s3_hls_queue_ctx = NULL;
static S3_HLS_BUFFER_CTX* s3_hls_buffer_ctx = NULL;
static S3_HLS_THREAD_CTX* s3_hls_worker_thread = NULL;
static S3_HLS_CLIENT_CTX* s3_client = NULL;

static sem_t s3_hls_put_send_sem;

static char* object_prefix = NULL;

static char object_key_buffer[S3_HLS_MAX_KEY_LENGTH + 1];

/*
 */
static void S3_HLS_Upload_Queue_Item() {
    SDK_DEBUG("Ready For Upload!\n");
    int32_t ret = sem_wait(&s3_hls_put_send_sem);
	if(0 != ret) {
	    SDK_DEBUG("Error Semaphore impared! %d\n", ret);
	}
	
    S3_HLS_BUFFER_PART_CTX part_ctx;
    ret = S3_HLS_Get_Item_From_Queue(s3_hls_queue_ctx, &part_ctx);

	if(S3_HLS_OK != ret) {
	    SDK_DEBUG("Failed to get item from queue!\n");
	    return;
	}

    struct tm* time_tm = gmtime(&part_ctx.timestamp);
    
    if(0 >= sprintf(object_key_buffer, S3_HLS_TS_OBJECT_KEY_FORMAT, object_prefix ? object_prefix : S3_HLS_SDK_EMPTY_STRING, time_tm->tm_year + 1900, time_tm->tm_mon + 1, time_tm->tm_mday, time_tm->tm_hour, time_tm->tm_min, time_tm->tm_sec)) {
        SDK_DEBUG("Unkown Internal Error!\n");
        return;
    }

	SDK_DEBUG("Get Queue Info!\n");
	SDK_DEBUG("Queue Info: %p, %d, %p, %d\n", part_ctx.first_part_start, part_ctx.first_part_length, part_ctx.second_part_start, part_ctx.second_part_length);
	S3_HLS_Client_Upload_Buffer(s3_client, object_key_buffer, part_ctx.first_part_start, part_ctx.first_part_length, part_ctx.second_part_start, part_ctx.second_part_length);
	
	SDK_DEBUG("Upload Complete, Clear Queue Buffer!\n");
	
	if(S3_HLS_OK != S3_HLS_Release_Queue(s3_hls_queue_ctx)) {
        SDK_DEBUG("Release Queue Failed!\n");
	    return;
	}

    if(S3_HLS_OK != S3_HLS_Lock_Buffer(s3_hls_buffer_ctx)) {
        SDK_DEBUG("Get Buffer Lock Failed!\n");
        return;
    }
    
    SDK_DEBUG("Release Buffer!\n");
    S3_HLS_Clear_Buffer(s3_hls_buffer_ctx, &part_ctx);
    
    if(S3_HLS_OK != S3_HLS_Unlock_Buffer(s3_hls_buffer_ctx)) {
        SDK_DEBUG("Get Buffer Unlock Failed!\n");
        return;
    }
}

/*
 */
static void  S3_HLS_Add_Buffer_To_Queue(S3_HLS_BUFFER_PART_CTX* ctx) {
    SDK_DEBUG("Adding buffer to queue!\n");
    if(NULL == ctx) {
        SDK_DEBUG("Invalid CTX!\n");
        return;
    }
    
    if(NULL == ctx->first_part_start && 0 != ctx->first_part_length) {
        SDK_DEBUG("Invalid First Part!\n");
        return;
    }

    if(NULL == ctx->second_part_start && 0 != ctx->second_part_length) {
        SDK_DEBUG("Invalid Second Part!\n");
        return;
    }
        
    if(0 == ctx->first_part_length + ctx->second_part_length) {
        SDK_DEBUG("Empty Part!\n");
        return;
    }
    
    int32_t ret = S3_HLS_Add_To_Queue(s3_hls_queue_ctx, ctx->first_part_start, ctx->first_part_length, ctx->second_part_start, ctx->second_part_length, ctx->timestamp);
    if(0 != ret) {
        // unknown error
        SDK_DEBUG("Add item to queue failed! %d\n", ret);
        return;
    }

    SDK_DEBUG("Added to queue!\n");

	ret = sem_post(&s3_hls_put_send_sem);
	if(0 != ret) {
	    SDK_DEBUG("Error, post semaphore failed! %d\n", ret);
	}
}

/*
 * Initialize S3 client
 * Parameters:
 *   region - provide the region code like "us-east-1" where the bucket is created
 *   bucket - name of video bucket
 *   prefix - path to store the video in the bucket. Usually this is the certificate iD of the IPC when using AWS IoT Things Management
 *   endpoint - optional parameter, if using default endpiont then can set this parameter to NULL
 *
 * Note:
 *   These paremeters are not allowed to change after initialized.
 */
int32_t S3_HLS_SDK_Initialize(uint32_t buffer_size, char* region, char* bucket, char* prefix, char* endpint) {
    SDK_DEBUG("SDK Init!\n");
    
    CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
    
    /* Check for errors */ 
    if(res != CURLE_OK) {
        SDK_DEBUG("CURL Init Failed!\n");
        goto l_cleanup_curl;
    }
    
    if(0 !=sem_init(&s3_hls_put_send_sem, 0 ,0)) {
        SDK_DEBUG("Semaphore Init Failed!\n");
        goto l_cleanup_curl;
    }
    
    SDK_DEBUG("SDK Buffer Init!\n");
    s3_hls_buffer_ctx = S3_HLS_Initialize_Buffer(buffer_size, S3_HLS_Add_Buffer_To_Queue);
    if(NULL == s3_hls_buffer_ctx) {
        SDK_DEBUG("Buffer Init Failed!\n");
        goto l_cleanup_curl;
    }
        
    SDK_DEBUG("SDK S3 Client Init!\n");
    // initialize S3 upload process
    s3_client = S3_HLS_Client_Initialize(region, bucket, endpint);
    if(NULL == s3_client) {
        SDK_DEBUG("S3 Client Init Failed!\n");
        goto l_finalize_buffer;
    }
    
    SDK_DEBUG("Upload Thread Init!\n");
    s3_hls_worker_thread = S3_HLS_Upload_Thread_Initialize(S3_HLS_Upload_Queue_Item);
    if(NULL == s3_hls_worker_thread) {
        SDK_DEBUG("Upload Thread Init Failed!\n");
        goto l_finalize_client;
    }
    
    s3_hls_queue_ctx = S3_HLS_Initialize_Queue();
    if(NULL == s3_hls_queue_ctx) {
        SDK_DEBUG("Upload Queue Init Failed!\n");
        goto l_finalize_client;
    }

	object_prefix = prefix;

    SDK_DEBUG("SDK Init Finished!\n");
    return S3_HLS_OK;
    
l_finalize_client:
    S3_HLS_Client_Finalize(s3_client);
    s3_client = NULL;

l_finalize_buffer:
    S3_HLS_Finalize_Buffer(s3_hls_buffer_ctx);
    s3_hls_buffer_ctx = NULL;
    
l_cleanup_curl:
    curl_global_cleanup();

    return S3_HLS_UNKNOWN_INTERNAL_ERROR;
}

/*
 * Update Credential used to connect to S3
 * The credential is locked during generating request headers for SIgnature V4. And will release the lock during uploading.
 * Parameter:
 *   ak - Access Key
 *   sk - Secret Access Key
 *   token - token generated by STS for temporary credential
 *
 * Note:
 *   Suggest to use this SDK with AWS IoT Things Management. JITP will be a good choice.
 *   Suggest to rotate credential several minutes/seconds before old credential expires to avoid unsuccessful upload
 */
int32_t S3_HLS_SDK_Set_Credential(char* ak, char* sk, char* token) {
    return S3_HLS_Client_Set_Credential(s3_client, ak, sk, token);
}

/*
 * Call this function to set upload tag for item
 */
int32_t S3_HLS_SDK_Set_Tag(char* object_tag) {
    return S3_HLS_Client_Set_Tag(s3_client, object_tag);
}

/*
 * Start a back ground thread for uploading
 */
int32_t S3_HLS_SDK_Start_Upload() {
    return S3_HLS_Upload_Thread_Start(s3_hls_worker_thread);
}

/*
 * Finalize will release resources allocated 
 * Note: Finalize will not free input parameter like ak, sk, token, region, bucket, prefix, endpoint etc.
 */
int32_t S3_HLS_SDK_Finalize() {
    S3_HLS_Flush_Buffer(s3_hls_buffer_ctx);
    
    S3_HLS_Upload_Thread_Stop(s3_hls_worker_thread);
    
    S3_HLS_Client_Finalize(s3_client);
    
    S3_HLS_Finalize_Buffer(s3_hls_buffer_ctx);

    S3_HLS_Finalize_Queue(s3_hls_queue_ctx);    

    sem_destroy(&s3_hls_put_send_sem);
    
    curl_global_cleanup();

    return S3_HLS_OK;
}

/*
 * User call this method to put video stream into buffer
 * The pack contains an array of H264 frames. 
 * For most of the time, each image pack will contain only one frame
 * But usually SPS/PPS/SEI frames comes together with I frame within a pack
 * In that case, the pack will contains 4 frames
 */
int32_t S3_HLS_SDK_Put_Video_Frame(S3_HLS_FRAME_PACK* pack) {
    return S3_HLS_Pes_Write_Video_Frame(s3_hls_buffer_ctx, pack);
}

/*
 * User call this method to put audio stream into buffer
 * Currently the only supported audio frame type is AAC encoded frame
 */
int32_t S3_HLS_SDK_Put_Audio_Frame(S3_HLS_FRAME_PACK* pack) {
    return S3_HLS_Pes_Write_Audio_Frame(s3_hls_buffer_ctx, pack);
}