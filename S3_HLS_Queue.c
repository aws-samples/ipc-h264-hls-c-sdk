#include "stdlib.h"
#include "stdio.h"
#include "S3_HLS_Queue.h"
#include "S3_HLS_Return_Code.h" 

#define S3_HLS_QUEUE_DEBUG

#ifdef S3_HLS_QUEUE_DEBUG
#define QUEUE_DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define QUEUE_DEBUG(x, ...)
#endif

S3_HLS_QUEUE_CTX* S3_HLS_Initialize_Queue() {
    QUEUE_DEBUG("Initializing Queue!\n");
    S3_HLS_QUEUE_CTX* ret = NULL;
    
    ret = (S3_HLS_QUEUE_CTX*)malloc(sizeof(S3_HLS_QUEUE_CTX));
    if(NULL == ret) {
        QUEUE_DEBUG("[Init]Failed to allocate queue context!\n");
        return ret;
    }
    
    ret->queue_pos = 0;
    ret->queue_length = 0;
    
    pthread_mutexattr_t mattr;
    if(0 != pthread_mutexattr_init(&mattr)) {
        QUEUE_DEBUG("[Init]Failed to initialize queue lock attribute!\n");
        free(ret);
        return NULL;
    }
    
    int32_t protocol;
    if(0 != pthread_mutexattr_getprotocol(&mattr, &protocol)) {
        QUEUE_DEBUG("[Init]Failed to get queue lock protocol!\n");
        free(ret);
        return NULL;
    }
    
    QUEUE_DEBUG("[Init]Queue Protocol: %d\n", protocol);
    
    if(0 != pthread_mutex_init(&ret->s3_hls_queue_lock, &mattr)) {
        QUEUE_DEBUG("[Init]Failed to initialize queue lock!\n");
        free(ret);
        return NULL;
    }
    
    for(uint32_t i = 0; i < S3_HLS_MAX_PARTS_IN_BUFFER; i++) {
        ret->queue[i].first_part_start = NULL;
        ret->queue[i].second_part_start = NULL;

        ret->queue[i].first_part_length = 0;
        ret->queue[i].second_part_length = 0;
        
        ret->queue[i].timestamp = 0;
    }
    
    return ret;
}

int32_t S3_HLS_Add_To_Queue(S3_HLS_QUEUE_CTX* ctx, uint8_t* first_part, uint32_t first_length, uint8_t* second_part, uint32_t second_length, time_t timestamp) {
    if(NULL == ctx) {
        QUEUE_DEBUG("[Add]Invalid Queue Context!\n");
        return S3_HLS_INVALID_PARAMETER;
    }
    
    QUEUE_DEBUG("[Add]Locking queue! %lu\n", pthread_self());
    int32_t ret = pthread_mutex_lock(&ctx->s3_hls_queue_lock);
    if(0 != ret) {
        QUEUE_DEBUG("[Add]Failed to lock queue lock! %d\n", ret);
        return ret;
    }
    
    QUEUE_DEBUG("Current queue length: %d\n", ctx->queue_length);
    if(ctx->queue_length == S3_HLS_MAX_PARTS_IN_BUFFER) {
        QUEUE_DEBUG("[Add]Queue is full!\n");
        ret = pthread_mutex_unlock(&ctx->s3_hls_queue_lock);
        if(0 != ret) {
            QUEUE_DEBUG("[Add]Unlock queue failed! %d\n", ret);
        }
        return S3_HLS_QUEUE_FULL; // queue is full
    }

    uint8_t current_pos = ctx->queue_pos + ctx->queue_length;
    if(current_pos >= S3_HLS_MAX_PARTS_IN_BUFFER)
        current_pos -= S3_HLS_MAX_PARTS_IN_BUFFER;

    ctx->queue[current_pos].first_part_start = first_part;
    ctx->queue[current_pos].first_part_length = first_length;
    ctx->queue[current_pos].second_part_start = second_part;
    ctx->queue[current_pos].second_part_length = second_length;
    ctx->queue[current_pos].timestamp = timestamp;

    QUEUE_DEBUG("Before increase length: %d\n", ctx->queue_length);

    ctx->queue_length++;
    
    QUEUE_DEBUG("Added to queue! length: %d\n", ctx->queue_length);
    
    QUEUE_DEBUG("[Add]Unlocking queue!%lu\n", pthread_self());
    ret = pthread_mutex_unlock(&ctx->s3_hls_queue_lock);
    if(0 != ret) {
        QUEUE_DEBUG("[Add]Failed to unlock queue lock! %d\n", ret);
        return ret;
    }
    
    return S3_HLS_OK;
}

int32_t S3_HLS_Release_Queue(S3_HLS_QUEUE_CTX* ctx) {
    if(NULL == ctx) {
        QUEUE_DEBUG("[Release]Invalid Queue Context!\n");
        return S3_HLS_INVALID_PARAMETER;
    }
    
    QUEUE_DEBUG("[Release]Locking queue!\n");
	int32_t ret = pthread_mutex_lock(&ctx->s3_hls_queue_lock);
    if(0 != ret) {
        // unknown error
        QUEUE_DEBUG("[Release]Get Queue Lock Failed! %d\n", ret);
        return ret;
    }
    
    if(ctx->queue_length > 0) {
        ctx->queue_pos ++;
        ctx->queue_length--;
        QUEUE_DEBUG("Released queue! length: %d\n", ctx->queue_length);
        
        if(S3_HLS_MAX_PARTS_IN_BUFFER == ctx->queue_pos)
            ctx->queue_pos = 0;
    } else {
        QUEUE_DEBUG("Queue is empty cannot release!\n");
    }
    
    QUEUE_DEBUG("[Release]Unlocking queue!\n");
    ret = pthread_mutex_unlock(&ctx->s3_hls_queue_lock);
    if(0 != ret) {
        // unknown error
        QUEUE_DEBUG("[Release]Get Queue Unlock Failed! %d\n", ret);
        return ret;
    }
    return S3_HLS_OK;
}

int32_t S3_HLS_Finalize_Queue(S3_HLS_QUEUE_CTX* ctx) {
    if(NULL == ctx) {
        return S3_HLS_INVALID_PARAMETER;
    }
    
    int32_t ret = pthread_mutex_destroy(&ctx->s3_hls_queue_lock);
    if(0 != ret) {
        QUEUE_DEBUG("Failed to destroy queue lock!\n");
    }
    
    free(ctx);
    
    return ret;
}

int32_t S3_HLS_Get_Item_From_Queue(S3_HLS_QUEUE_CTX* ctx, S3_HLS_BUFFER_PART_CTX* buffer_ctx) {
    QUEUE_DEBUG("Get Item From Queue!\n");
    if(NULL == ctx || NULL == buffer_ctx) {
        QUEUE_DEBUG("Invalid Queue Context!\n");
        return S3_HLS_INVALID_PARAMETER;
    }
    
    QUEUE_DEBUG("[Get]Locking queue!\n");
    int32_t ret = pthread_mutex_lock(&ctx->s3_hls_queue_lock);
    if(0 != ret) {
        QUEUE_DEBUG("[Get]Failed to lock queue lock! %d\n", ret);
        return ret;
    }
    
    
    if(0 == ctx->queue_length) {
        QUEUE_DEBUG("[Get]Queue is Empty!\n");
        ret = pthread_mutex_unlock(&ctx->s3_hls_queue_lock);
        if(0 != ret) {
            QUEUE_DEBUG("[Get]Unlock queue failed! %d\n", ret);
        }
        buffer_ctx->first_part_start = NULL;
        buffer_ctx->first_part_length = 0;
        buffer_ctx->second_part_start = NULL;
        buffer_ctx->second_part_length = 0;
        buffer_ctx->timestamp = 0;
        return ret; // queue is full
    }

    buffer_ctx->first_part_start = ctx->queue[ctx->queue_pos].first_part_start;
    buffer_ctx->first_part_length = ctx->queue[ctx->queue_pos].first_part_length;
    buffer_ctx->second_part_start = ctx->queue[ctx->queue_pos].second_part_start;
    buffer_ctx->second_part_length = ctx->queue[ctx->queue_pos].second_part_length;
    buffer_ctx->timestamp = ctx->queue[ctx->queue_pos].timestamp;

    QUEUE_DEBUG("[Get]Unlocking queue!\n");
    ret = pthread_mutex_unlock(&ctx->s3_hls_queue_lock);
    if(0 != ret) {
        QUEUE_DEBUG("[Get]Failed to unlock queue lock! %d\n", ret);
        return ret;
    }

    return S3_HLS_OK;
}
