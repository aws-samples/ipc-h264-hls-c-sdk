#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#include "S3_HLS_Buffer_Mgr.h"
#include "S3_HLS_Return_Code.h" 

#define S3_HLS_BUFFER_FLUSH_CLEAR_DEBUG

#ifdef S3_HLS_BUFFER_FLUSH_CLEAR_DEBUG
#define BUFFER_FLUSH_DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define BUFFER_FLUSH_DEBUG(x, ...)
#endif

//#define S3_HLS_BUFFER_DEBUG

#ifdef S3_HLS_BUFFER_DEBUG
#define BUFFER_DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define BUFFER_DEBUG(x, ...)
#endif

/*
 * Buffer manager is a central managememnt of video and audio buffer that is cached for sending to S3
 * Initialize will allocate memory buffer for given size
 */
S3_HLS_BUFFER_CTX* S3_HLS_Initialize_Buffer(uint32_t buffer_size, BUFFER_CALL_BACK function_pointer) {
    BUFFER_DEBUG("Initializing Buffer!\n");
    S3_HLS_BUFFER_CTX* ret = NULL;
    ret = (S3_HLS_BUFFER_CTX*)malloc(sizeof(S3_HLS_BUFFER_CTX));
    if(NULL == ret) {
        BUFFER_DEBUG("Failed to allocate buffer context!\n");
        return ret;
    }
    
    ret->buffer_start = (uint8_t*)malloc(buffer_size);
    if(NULL == ret->buffer_start) {
        BUFFER_DEBUG("Failed to allocate buffer!\n");
        free(ret);
        return NULL;
    }
    
    if(0 != pthread_mutex_init(&ret->buffer_lock, NULL)) {
        BUFFER_DEBUG("Failed to initialize buffer lock!\n");
        free(ret->buffer_start);
        free(ret);
        return NULL;
    }
    
    ret->total_length = buffer_size;

    ret->used_start = ret->buffer_start;
    ret->used_length = 0;
    
    ret->last_flush = ret->buffer_start;
    
    BUFFER_DEBUG("Callback function address %ld", function_pointer);
    ret->call_back = function_pointer;

    return ret;
}

/*
 * Buffer manager is a central managememnt of video and audio buffer that is cached for sending to S3
 * Initialize will allocate memory buffer for given size
 */
void S3_HLS_Finalize_Buffer(S3_HLS_BUFFER_CTX* ctx) {
    pthread_mutex_destroy(&ctx->buffer_lock);

    free(ctx->buffer_start);
    free(ctx);
}

/*
 * Flush buffer will switch the partition of buffer that pending send out and 
 * buffer that is currently put data into
 */
int32_t S3_HLS_Flush_Buffer(S3_HLS_BUFFER_CTX* ctx) {
    BUFFER_FLUSH_DEBUG("Flushing buffer!\n");
    if(NULL == ctx)
        return S3_HLS_INVALID_PARAMETER;

    uint8_t* cur_pos = ctx->used_start + ctx->used_length;
    if(NULL == ctx->last_flush) {
        BUFFER_FLUSH_DEBUG("Invalid last flush time!\n");
        return S3_HLS_INVALID_PARAMETER; // valid ctx will contain last_flush
    }
        
    if(0 == ctx->used_length) {
        BUFFER_FLUSH_DEBUG("Buffer is empty!\n");
        time(&ctx->last_flush_timestamp);
        return S3_HLS_OK;
    }
    
    if(ctx->last_flush != cur_pos) { // avoid duplicate flush especially when buffer is full
        if(NULL != ctx->call_back) {
            BUFFER_FLUSH_DEBUG("Calling callback function!\n");
            S3_HLS_BUFFER_PART_CTX part_ctx;
            if(cur_pos >= ctx->buffer_start + ctx->total_length) 
                cur_pos -= ctx->total_length;
                
            if(ctx->last_flush < cur_pos) {
                part_ctx.first_part_start = ctx->last_flush;
                part_ctx.first_part_length = cur_pos - ctx->last_flush;
                
                part_ctx.second_part_start = NULL;
                part_ctx.second_part_length = 0;
            } else { // acrossed ring buffer boundary
                part_ctx.first_part_start = ctx->last_flush;
                part_ctx.first_part_length = ctx->buffer_start + ctx->total_length - ctx->last_flush;
                
                part_ctx.second_part_start = ctx->buffer_start;
                part_ctx.second_part_length = cur_pos - ctx->buffer_start;
            }
            
            part_ctx.timestamp = ctx->last_flush_timestamp;
            
            ctx->call_back(&part_ctx);
            printf("Flush Buffer %ld, %ld, %d, %ld, %d\n", ctx->last_flush, part_ctx.first_part_start, part_ctx.first_part_length, part_ctx.second_part_start, part_ctx.second_part_length);
        }
    
        ctx->last_flush = cur_pos;
        time(&ctx->last_flush_timestamp);
    }

    return S3_HLS_OK;
}

/*
 * Clear buffer will release buffer that provided by flush buffer
 * After clear the buffer, it can be reused by other input
 */
int32_t S3_HLS_Clear_Buffer(S3_HLS_BUFFER_CTX* buffer_ctx, S3_HLS_BUFFER_PART_CTX* part_ctx) {
    BUFFER_FLUSH_DEBUG("Clear Buffer!\n");
    if(NULL == buffer_ctx || NULL == part_ctx)
        return S3_HLS_INVALID_PARAMETER;

    if(NULL == part_ctx->second_part_start && 0 < part_ctx->second_part_length)
        return S3_HLS_INVALID_PARAMETER;

    // Only support clear buffer in sequence, not support clear buffer in middle of used buffer
    printf("Clear Buffer %ld, %d, %ld, %d\n", part_ctx->first_part_start, part_ctx->first_part_length, part_ctx->second_part_start, part_ctx->second_part_length);
    if(buffer_ctx->used_start != part_ctx->first_part_start) {
        printf("Clear buffer not match start! %ld, %ld\n", buffer_ctx->used_start, part_ctx->first_part_start);
    }
    
    uint8_t* next_start = (NULL == part_ctx->second_part_start) ? (part_ctx->first_part_start + part_ctx->first_part_length) : (part_ctx->second_part_start + part_ctx->second_part_length);
    if(next_start > buffer_ctx->used_start) {
        buffer_ctx->used_length -= (next_start - buffer_ctx->used_start);
    } else if(next_start < buffer_ctx->used_start) {
        buffer_ctx->used_length -= buffer_ctx->total_length - (buffer_ctx->used_start - next_start);
    }
    
    buffer_ctx->used_start = next_start;
/*        
    uint32_t release_length = (part_ctx->first_part_length + part_ctx->second_part_length);
    
    buffer_ctx->used_length -= release_length;
    buffer_ctx->used_start += release_length;
*/    
    printf("Buffer Info: %ld, %ld, %ld, %d\n", buffer_ctx->used_start, buffer_ctx->used_length, buffer_ctx->buffer_start, buffer_ctx->total_length);
    if(buffer_ctx->used_start >= buffer_ctx->buffer_start + buffer_ctx->total_length) {
        buffer_ctx->used_start -= buffer_ctx->total_length;
    }
    printf("New Buffer Start: %ld\n", buffer_ctx->used_start);

    return S3_HLS_OK;
}

/*
 * Put data into buffer
 */
int32_t S3_HLS_Put_To_Buffer(S3_HLS_BUFFER_CTX* ctx, char* data, uint32_t length) {
    BUFFER_DEBUG("Putting Buffer!\n");
    if(NULL == ctx) {
        BUFFER_DEBUG("Invalid Buffer Context!\n");
        return S3_HLS_INVALID_PARAMETER;
    }
    
    if(NULL == data && 0 < length) {
        BUFFER_DEBUG("Input data address is NULL, but length is not 0\n");
        return S3_HLS_INVALID_PARAMETER;
    }
    
    // lock is handled outside put if necessary
    if(ctx->total_length < ctx->used_length + length) {
        BUFFER_DEBUG("Buffer is full, currently used %d, new data %d\n", ctx->used_length, length);
        return S3_HLS_BUFFER_OVERFLOW;
    }

    BUFFER_DEBUG("Copy Buffer!\n");
    uint8_t* buffer_end = ctx->buffer_start + ctx->total_length;
    uint8_t* current = ctx->used_start + ctx->used_length;
    if(current >= buffer_end)
        current -= ctx->total_length;
        
    if(buffer_end - current < length) {
        // acrossed ring buffer boundary
        memcpy(current, data, buffer_end - current);
        memcpy(ctx->buffer_start, data + (buffer_end - current), length - (buffer_end - current));
    } else {
        memcpy(current, data, length);
    }
    
    ctx->used_length += length;

    return length;
}

int32_t S3_HLS_Lock_Buffer(S3_HLS_BUFFER_CTX* ctx) {
    if(NULL == ctx) {
        return S3_HLS_INVALID_PARAMETER;
    }
    
    return pthread_mutex_lock(&ctx->buffer_lock);
}

int32_t S3_HLS_Unlock_Buffer(S3_HLS_BUFFER_CTX* ctx) {
    if(NULL == ctx) {
        return S3_HLS_INVALID_PARAMETER;
    }
    
    return pthread_mutex_unlock(&ctx->buffer_lock);
}

