#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "S3_HLS_Return_Code.h"
#include "S3_HLS_S3_Put_Client.h"
#include "S3_Crypto.h"

#define S3_HLS_CURL_CONNECTION_TIMEOUT                      4
#define S3_HLS_CURL_TRANSFER_TIMEOUT                        4

#define S3_HLS_HTTPS_URI_FORMAT                             "https://%s%s"

#define S3_HLS_ENDPOINT_FORMAT                              "%s.s3.%s.amazonaws.com%s" // bucket, region, cn or global postfix
#define S3_HLS_EMPTY_STRING                                 ""
#define S3_HLS_CHINA_REGION_POSTFIX                         ".cn"

#define S3_HLS_CANONICAL_REQUEST_NEW_LINE                   "\n"

#define S3_SERVICE_KEY                                      "s3"
#define AWS_SIGV4_REQUEST                                   "aws4_request"

#define S3_HLS_CANONICAL_REQUEST_METHOD                     "PUT"

#define S3_HLS_HOST_HEADER_FORMAT                           "host:%s" // endpoint, object key
#define S3_HLS_RANGE_HEADER_FORMAT                          "range:"

#define S3_HLS_HEX_HASH_STIRNG_LENGTH                       64
#define S3_HLS_CONTENT_SHA256_HEADER_FORMAT                 "x-amz-content-sha256:%s"
#define S3_HLS_CONTENT_SHA256_HASH_OFFSET                   21 // hash hex string starts at the 21th position

#define S3_HLS_DATE_FORMAT                                  "%04d%02d%02d"
#define S3_HLS_TIMESTAMP_HEADER_FORMAT                      "x-amz-date:%04d%02d%02dT%02d%02d%02dZ"
#define S3_HLS_TIMESTAMP_VALUE_OFFSET                       11 // date starts at the 11th position

#define S3_HLS_CANONICAL_REQUEST_SIGNED_HEADERS_FORMAT      "host;range;x-amz-content-sha256;x-amz-date"

#define S3_HLS_TOKEN_HEADER_IN_CANONICAL_REQUEST            ";x-amz-security-token"
#define S3_HLS_TOKEN_HEADER_FORMAT                          "x-amz-security-token:%s"

#define S3_HLS_TAG_HEADER_IN_CANONICAL_REQUEST              ";x-amz-tagging"
#define S3_HLS_TAG_HEADER_FORMAT                            "x-amz-tagging:%s"

#define S3_HLS_AUTHENTICATION_HEADER_FORMAT                 "Authorization:AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date%s%s,Signature=%s" // ak, date in yyyyMMdd, region, optional token heade, signature hex string

#define S3_HLS_SECRET_ACCESS_KEY_FORMAT                     "AWS4%s" // sk

#define S3_HLS_STRING_TO_SIGN_FORMAT                        "AWS4-HMAC-SHA256\n%s\n%s/%s/s3/aws4_request\n%s" // timestamp in yyyyMMddThhmmssZ, date in yyyyMMdd, region, hex string of canonical request hash

#define S3_HLS_DUMMY_TIMESTAMP                              "20210605T124806Z"
#define S3_HLS_DUMMY_DATE                                   "20210605"

//#define S3_HLS_S3_PUT_DEBUG

#ifdef S3_HLS_S3_PUT_DEBUG
#define PUT_DEBUG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define PUT_DEBUG(x, ...)
#endif

typedef struct s3_hls_upload_buffer_s{
    uint8_t* first_part_start;      // start of the buffer address
    uint32_t first_part_length;     // the length of the first part video buffer
    
    uint8_t* second_part_start;     // when using ring buffer there might have second part of video buffer
    uint32_t second_part_length;    // if not using ring buffer, just set second_part_start to NULL and set second_part_length to 0
    
    uint32_t pos;
} S3_HLS_UPLOAD_CTX;

static size_t S3_HLS_Upload_Data(void *ptr, size_t size, size_t nmemb, void *stream) {
    S3_HLS_UPLOAD_CTX* ctx = (S3_HLS_UPLOAD_CTX*)stream;
    PUT_DEBUG("Upload Data! %d %d %d %ld\n", size, nmemb, ctx->pos, stream);
    
    if(NULL == ctx->first_part_start && 0 != ctx->first_part_length) {
        return S3_HLS_INVALID_PARAMETER;
    }
    
    if(NULL == ctx->second_part_start && 0 != ctx->second_part_length) {
        return S3_HLS_INVALID_PARAMETER;
    }
    
    if(ctx->pos == ctx->first_part_length + ctx->second_part_length) {
        PUT_DEBUG("Upload Data Done! %d\n", ctx->pos);
        return 0;
    }
    
    if(0 == size || 0 == nmemb || (size*nmemb) < 1) {
        return 0;
    }
    
    size_t len = size * nmemb;
    size_t bytes_written = 0;
    if(ctx->pos < ctx->first_part_length) {
        size_t bytes_to_write = len <= (ctx->first_part_length - ctx->pos) ? len : (ctx->first_part_length - ctx->pos);
        memcpy(ptr, ctx->first_part_start + ctx->pos, bytes_to_write);
        ctx->pos += bytes_to_write;
        len -= bytes_to_write;
        ptr += bytes_to_write;
        
        bytes_written += bytes_to_write;
    }
    
    if(len > 0) {
        if(ctx->pos < ctx->first_part_length + ctx->second_part_length) { // write in second part
        size_t bytes_to_write = len <= (ctx->first_part_length + ctx->second_part_length - ctx->pos) ? len : (ctx->first_part_length + ctx->second_part_length - ctx->pos);
            memcpy(ptr, ctx->second_part_start + (ctx->pos - ctx->first_part_length), bytes_to_write);
            ctx->pos += bytes_to_write;
            bytes_written += bytes_to_write;
        }
    }
    
    PUT_DEBUG("Upload Bytes Written: %d\n", bytes_written);
    return bytes_written;
}                                                                    

S3_HLS_CLIENT_CTX* S3_HLS_Client_Initialize(char* region, char* bucket, char* endpoint) {
    PUT_DEBUG("Initializing S3 Client!\n");
    if(NULL == region || NULL == bucket || strlen(region) < 3) {
        return NULL;
    }
    
    PUT_DEBUG("Allocate Client CTX!\n");
    S3_HLS_CLIENT_CTX* ret = (S3_HLS_CLIENT_CTX*)malloc(sizeof(S3_HLS_CLIENT_CTX));
    if(NULL == ret) {
        PUT_DEBUG("Failed to allocate memory for client context!\n");
        return NULL;
    }
    
    // set ctx initial values
    ret->endpoint = NULL;
    ret->free_endpoint = 0;
    
    ret->host_header = NULL;
    ret->string_to_sign = NULL;
    ret->region = NULL;
    
    ret->secret_access_key = NULL;
    ret->secret_access_key_length = 0;
    
    ret->token_header = NULL;
    ret->token_header_length = 0;
    
    ret->auth_header = NULL;
    ret->auth_header_length = 0;
    
    ret->access_key = NULL;
    
    ret->tag_header = NULL;
    ret->tag_header_length = 0;
    
    ret->curl = NULL;
    
/*    ret->curl = curl_easy_init();
    curl_easy_setopt(ret->curl, CURLOPT_READFUNCTION, S3_HLS_Upload_Data);
    
    if(NULL == ret->curl) {
        PUT_DEBUG("Failed to initialize curl!\n");
        goto l_free_ctx;
    }*/
    
    if(0 != pthread_mutex_init(&ret->credential_lock, NULL)) {
        PUT_DEBUG("Failed to initialize credential lock!\n");
        goto l_free_ctx;
    }
    
    int32_t length = 0;

    PUT_DEBUG("Generate Endpoints!\n");
    // Generate endpoint field
    if(NULL == endpoint) { // need generate endpoint using region and bucket name
        char* postfix = S3_HLS_EMPTY_STRING;
        if('c' == region[0] && 'n' == region[1] && '-' == region[2]) { // it's china mainland region
            postfix = S3_HLS_CHINA_REGION_POSTFIX;
        }
        
        length = snprintf(NULL, 0, S3_HLS_ENDPOINT_FORMAT, bucket, region, postfix);
        if(0 >= length) {
            PUT_DEBUG("Invalid ret value from snprintf %d!\n", length);
            goto l_free_ctx;
        }
        
        ret->endpoint = (char*)malloc(length + 1);
        if(NULL == ret->endpoint) {
            PUT_DEBUG("Out of memory!!\n");
            goto l_free_ctx;
        }
        
        ret->free_endpoint = 1;
        length = sprintf(ret->endpoint, S3_HLS_ENDPOINT_FORMAT, bucket, region, postfix);
        if(0 >= length) {
            PUT_DEBUG("Invalid ret value from snprintf %d!\n", length);
            goto l_free_endpoint;
        }
    } else {
        ret->endpoint = endpoint;
    }
    
    PUT_DEBUG("Generate Host Header!\n");
    length = snprintf(NULL, 0, S3_HLS_HOST_HEADER_FORMAT, ret->endpoint);
    if(0 >= length) 
        goto l_free_endpoint;

    ret->host_header = (char*)malloc(length + 1); // for null pointer
    if(NULL == ret->host_header)
        goto l_free_endpoint;

    if(0 >= sprintf(ret->host_header, S3_HLS_HOST_HEADER_FORMAT, ret->endpoint)) 
        goto l_free_host_header;

    PUT_DEBUG("Endpoint: %s\n", ret->endpoint);
    
    PUT_DEBUG("Allocate String To Sign Buffer!\n");
    length = snprintf(NULL, 0, S3_HLS_STRING_TO_SIGN_FORMAT, S3_HLS_DUMMY_TIMESTAMP, S3_HLS_DUMMY_DATE, region, S3_HLS_EMPTY_STRING);
    if(0 >= length) {
        PUT_DEBUG("Unable To Get String To Sign Length!\n");
        goto l_free_host_header;
    }

    length += S3_HLS_HEX_HASH_STIRNG_LENGTH; // Hash string used in format is empty string
    
    ret->string_to_sign = (char*)malloc(length + 1); // null terminator
    if(NULL == ret->string_to_sign) {
        PUT_DEBUG("Unable To Allocate Buffer For String To Sign!\n");
        goto l_free_host_header;
    }
        
    length = snprintf(NULL, 0, S3_HLS_HTTPS_URI_FORMAT, ret->endpoint, S3_HLS_EMPTY_STRING);
    if(0 >= length) {
        PUT_DEBUG("Unable To Get HTTPS URI Length!\n");
        goto l_free_string_to_sign;
    }
        
    length += S3_HLS_MAX_KEY_LENGTH;
    ret->uri = (char*)malloc(length + 1); // null terminator
    if(NULL == ret->uri) {
        PUT_DEBUG("Unable To Allocate Memory For HTTPS URI!\n");
        goto l_free_string_to_sign;
    }
    
    /// no need to actual assign value for string to sign. will assign value when upload object
    ret->region = region;
    
    return ret;

l_free_string_to_sign: 
    free(ret->string_to_sign);
    
l_free_host_header:
    free(ret->host_header);
    
l_free_endpoint:
    if(ret->free_endpoint)
        free(ret->endpoint);
        
    pthread_mutex_destroy(&ret->credential_lock);
    curl_easy_cleanup(ret->curl);
    
l_free_ctx:
    free(ret);
    
    return NULL;
}

int32_t S3_HLS_Client_Finalize(S3_HLS_CLIENT_CTX* ctx) {
    if(NULL != ctx->curl)
        curl_easy_cleanup(ctx->curl);
    
    if(NULL != ctx->uri)
        free(ctx->uri);
        
    if(NULL != ctx->auth_header)
        free(ctx->auth_header);
    
    if(NULL != ctx->token_header)
        free(ctx->token_header);
        
    if(NULL != ctx->tag_header)
        free(ctx->tag_header);
    
    if(NULL != ctx->secret_access_key)
        free(ctx->secret_access_key);

    if(ctx->free_endpoint)
        free(ctx->endpoint);
        
    if(NULL != ctx->string_to_sign)
        free(ctx->string_to_sign);
        
    if(NULL != ctx->host_header)
        free(ctx->host_header);

    free(ctx);
    
    return S3_HLS_OK;
}

int32_t S3_HLS_Client_Set_Tag(S3_HLS_CLIENT_CTX* ctx, char* object_tag) {
    if(NULL == ctx)
        return S3_HLS_INVALID_PARAMETER;
        
    int32_t ret = S3_HLS_OK;
    if(0 != pthread_mutex_lock(&ctx->credential_lock))
        return S3_HLS_LOCK_FAILED;

    if(NULL == object_tag) {
        if(NULL != ctx->tag_header) {
            free(ctx->tag_header);
            ctx->tag_header = NULL;
            ctx->tag_header_length = 0;
        }
        
        goto l_unlock;
    }

    uint32_t tag_length = snprintf(NULL, 0, S3_HLS_TAG_HEADER_FORMAT, object_tag);
    if(0 >= tag_length) {
        ret = S3_HLS_UNKNOWN_INTERNAL_ERROR;
        goto l_unlock;
    }
    
    tag_length++;
    
    char* temp_header = NULL;
    if(tag_length <= ctx->tag_header_length) { // new tag have same length or shorter, no need to change length only update content
        tag_length = sprintf(ctx->tag_header, S3_HLS_TAG_HEADER_FORMAT, object_tag);
        if(0 >= tag_length) {
            PUT_DEBUG("Setting Tag Header In CTX Failed\n");
            ret = S3_HLS_UNKNOWN_INTERNAL_ERROR;
        }

        goto l_unlock;
    }
    
    temp_header = (char*)malloc(tag_length);
    if(NULL == temp_header) {
        PUT_DEBUG("Allocate Space For Tag Header Failed\n");
        ret = S3_HLS_UNKNOWN_INTERNAL_ERROR;
        goto l_unlock;
    }

    tag_length = sprintf(temp_header, S3_HLS_TAG_HEADER_FORMAT, object_tag);
    if(0 >= tag_length) {
        PUT_DEBUG("Setting Tag Header Failed\n");
        ret = S3_HLS_UNKNOWN_INTERNAL_ERROR;
        free(temp_header);
        goto l_unlock;
    }

    if(NULL != ctx->tag_header) {
        free(ctx->tag_header);
    }
    
    ctx->tag_header = temp_header;
    ctx->tag_header_length = tag_length;

l_unlock:
    pthread_mutex_unlock(&ctx->credential_lock);
    return ret;
}

int32_t S3_HLS_Client_Set_Credential(S3_HLS_CLIENT_CTX* ctx, char* ak, char* sk, char* token) {
    PUT_DEBUG("Setting Credential!\n");

    if(NULL == ctx || NULL == ak || NULL == sk)
        return S3_HLS_INVALID_PARAMETER;
        
    int32_t ret = S3_HLS_OK;
    
    uint32_t secret_access_key_length = snprintf(NULL, 0, S3_HLS_SECRET_ACCESS_KEY_FORMAT, sk);
    if(0 >= secret_access_key_length) {
        PUT_DEBUG("Setting Access Key Failed\n");
        return S3_HLS_UNKNOWN_INTERNAL_ERROR;
    }

    uint32_t token_header_length = 0;
    if(NULL != token) {
        token_header_length = snprintf(NULL, 0, S3_HLS_TOKEN_HEADER_FORMAT, token);
        if(0 >= token_header_length) {
            PUT_DEBUG("Setting Token Failed\n");
            return S3_HLS_UNKNOWN_INTERNAL_ERROR;
        }
    }

    // lock credential lock
    if(0 != pthread_mutex_lock(&ctx->credential_lock))
        return S3_HLS_LOCK_FAILED;

    uint32_t auth_header_length = snprintf(
                                                NULL, 
                                                0, 
                                                S3_HLS_AUTHENTICATION_HEADER_FORMAT, 
                                                ak, 
                                                S3_HLS_DUMMY_DATE, 
                                                ctx->region, 
                                                S3_HLS_TOKEN_HEADER_IN_CANONICAL_REQUEST, 
                                                S3_HLS_TAG_HEADER_IN_CANONICAL_REQUEST,
                                                S3_HLS_EMPTY_STRING
                                            );
    if(0 >= auth_header_length) {
        PUT_DEBUG("Setting Authorization Header Failed\n");
        return S3_HLS_UNKNOWN_INTERNAL_ERROR;
    }

    // add additional length for hash
    auth_header_length += S3_HLS_HEX_HASH_STIRNG_LENGTH;

    secret_access_key_length++;
    auth_header_length++;
    
    if(token_header_length > 0)
        token_header_length++;


    PUT_DEBUG("Buffer Length: Token Header: %d, SK: %d, Auth Header %d!\n", token_header_length, secret_access_key_length, auth_header_length);

    // start allocate memory if necessary
    char* temp_secret_access_key = NULL;
    char* temp_token_header = NULL;
    char* temp_auth_header = NULL;
    
    if(secret_access_key_length > ctx->secret_access_key_length) {
        temp_secret_access_key = (char*)malloc(secret_access_key_length);
        if(NULL == temp_secret_access_key) {
            ret = S3_HLS_OUT_OF_MEMORY;
            goto l_unlock;
        }
    }
    
    if(NULL != token) {
        if(token_header_length > ctx->token_header_length) {
            temp_token_header = (char*)malloc(token_header_length);
            if(NULL == temp_token_header) {
                ret = S3_HLS_OUT_OF_MEMORY;
                
                if(NULL != temp_secret_access_key)
                    free(temp_secret_access_key);
                    
                goto l_unlock;
            }
        }
    }

    if(auth_header_length > ctx->auth_header_length) {
        temp_auth_header = (char*)malloc(auth_header_length);
        if(NULL == temp_auth_header) {
            ret = S3_HLS_OUT_OF_MEMORY;
            
            if(NULL != temp_secret_access_key)
                free(temp_secret_access_key);
                
            if(NULL != temp_token_header)
                free(temp_token_header);
                
            goto l_unlock;
        }
    }

    // update pointer and length marks
    if(NULL != temp_secret_access_key) {
        if(NULL != ctx->secret_access_key) {
            free(ctx->secret_access_key);
        }
        
        ctx->secret_access_key = temp_secret_access_key;
        ctx->secret_access_key_length = secret_access_key_length;
    }
    
    if(NULL != temp_token_header) {
        if(NULL != ctx->token_header) {
            free(ctx->token_header);
        }

        ctx->token_header = temp_token_header;
        ctx->token_header_length = token_header_length;
    }
    
    if(NULL != temp_auth_header) {
        if(NULL != ctx->auth_header) {
            free(ctx->auth_header);
        }

        ctx->auth_header = temp_auth_header;
        ctx->auth_header_length = auth_header_length;
    }
    
    // Start writing to variables
    uint32_t length = sprintf(ctx->secret_access_key, S3_HLS_SECRET_ACCESS_KEY_FORMAT, sk);
    if(0 >= length) {
        PUT_DEBUG("Print SK Failed\n");
        ret = S3_HLS_UNKNOWN_INTERNAL_ERROR;
        goto l_unlock;
    }
    
    if(NULL != token) {
        length = sprintf(ctx->token_header, S3_HLS_TOKEN_HEADER_FORMAT, token);
        if(0 >= length) {
            PUT_DEBUG("Print Token Header Failed\n");
            ret = S3_HLS_UNKNOWN_INTERNAL_ERROR;
            goto l_unlock;
        }
    } else if(NULL != ctx->token_header) { // in case of last token is not null and new one is null
        free(ctx->token_header);
        ctx->token_header = NULL;
        ctx->token_header_length = 0;
    }
    
    // auth header only need to allocate space
    
    ctx->access_key = ak;

    PUT_DEBUG("AK: %s\n", ctx->access_key);
    PUT_DEBUG("SK: %s\n", ctx->secret_access_key);
    
    if(NULL != ctx->token_header) {
        PUT_DEBUG("Token: %s\n", ctx->token_header);
    }

l_unlock:
    pthread_mutex_unlock(&ctx->credential_lock);
    
    return ret;
}

static int32_t S3_HLS_Hash_Put_Canonical_Request(S3_HLS_CLIENT_CTX* ctx, char* object_key, S3_SHA256_HASH result) {
    S3_SHA256_CTX sha256_ctx;
    S3_SHA256_Init(&sha256_ctx);

    PUT_DEBUG("Hash Canonical Request:\n");

    // PUT\n    
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_METHOD);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_METHOD, strlen(S3_HLS_CANONICAL_REQUEST_METHOD));        // PUT
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));    // \n

    // Canonical object key\n
    PUT_DEBUG("%s", object_key);
    S3_SHA256_Update(&sha256_ctx, object_key, strlen(object_key));
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));

    // Canonical Query String\n
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));
    
    // Headers
    /*
    // Content=Length
    PUT_DEBUG("%s", s3_hls_content_length_header_buffer);
    S3_SHA256_Update(&sha256_ctx, s3_hls_content_length_header_buffer, strlen(s3_hls_content_length_header_buffer));
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));
    */
    // Host
    PUT_DEBUG("%s", ctx->host_header);
    S3_SHA256_Update(&sha256_ctx, ctx->host_header, strlen(ctx->host_header));
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));

    // Range
    PUT_DEBUG("%s", S3_HLS_RANGE_HEADER_FORMAT);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_RANGE_HEADER_FORMAT, strlen(S3_HLS_RANGE_HEADER_FORMAT));
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));

    // Content Hash
    PUT_DEBUG("%s", ctx->content_hash);
    S3_SHA256_Update(&sha256_ctx, ctx->content_hash, strlen(ctx->content_hash));
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));

    // Request Time
    PUT_DEBUG("%s", ctx->timestamp_buffer);
    S3_SHA256_Update(&sha256_ctx, ctx->timestamp_buffer, strlen(ctx->timestamp_buffer));
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));
    
    if(NULL != ctx->token_header) {
        PUT_DEBUG("%s", ctx->token_header);
        S3_SHA256_Update(&sha256_ctx, ctx->token_header, strlen(ctx->token_header));
        PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
        S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));
    }

    if(NULL != ctx->tag_header) {
        PUT_DEBUG("%s", ctx->tag_header);
        S3_SHA256_Update(&sha256_ctx, ctx->tag_header, strlen(ctx->tag_header));
        PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
        S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));
    }

    // Headers End
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));
    
    // Signed Headers
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_SIGNED_HEADERS_FORMAT);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_SIGNED_HEADERS_FORMAT, strlen(S3_HLS_CANONICAL_REQUEST_SIGNED_HEADERS_FORMAT));

    if(NULL != ctx->token_header) {
        PUT_DEBUG("%s", S3_HLS_TOKEN_HEADER_IN_CANONICAL_REQUEST);
        S3_SHA256_Update(&sha256_ctx, S3_HLS_TOKEN_HEADER_IN_CANONICAL_REQUEST, strlen(S3_HLS_TOKEN_HEADER_IN_CANONICAL_REQUEST)); // ;
    }

    if(NULL != ctx->tag_header) {
        PUT_DEBUG("%s", S3_HLS_TAG_HEADER_IN_CANONICAL_REQUEST);
        S3_SHA256_Update(&sha256_ctx, S3_HLS_TAG_HEADER_IN_CANONICAL_REQUEST, strlen(S3_HLS_TAG_HEADER_IN_CANONICAL_REQUEST));
    }
    
    // Signed Headers Finished
    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);
    S3_SHA256_Update(&sha256_ctx, S3_HLS_CANONICAL_REQUEST_NEW_LINE, strlen(S3_HLS_CANONICAL_REQUEST_NEW_LINE));
    
    // Hash Payload Finished
    PUT_DEBUG("%s", ctx->content_hash + S3_HLS_CONTENT_SHA256_HASH_OFFSET);
    S3_SHA256_Update(&sha256_ctx, ctx->content_hash + S3_HLS_CONTENT_SHA256_HASH_OFFSET, strlen(ctx->content_hash + S3_HLS_CONTENT_SHA256_HASH_OFFSET));

    PUT_DEBUG("%s", S3_HLS_CANONICAL_REQUEST_NEW_LINE);

    return S3_SHA256_Final(&sha256_ctx, result);
}

int32_t S3_HLS_Client_Upload_Buffer(S3_HLS_CLIENT_CTX* ctx, char* object_key, uint8_t* first_data, uint32_t first_length, uint8_t* second_data, uint32_t second_length) {
    uint8_t retry_flag = 0;

    PUT_DEBUG("Upload start!\n");
    PUT_DEBUG("Validate parameters\n");
    if(NULL == ctx || NULL == object_key || NULL == first_data)
        return S3_HLS_INVALID_PARAMETER;
        
    if(0 == strlen(object_key))
        return S3_HLS_INVALID_PARAMETER;
        
    if('/' != object_key[0])
        return S3_HLS_INVALID_PARAMETER;
        
    if(NULL == second_data && 0 != second_length)
        return S3_HLS_INVALID_PARAMETER;
        
    PUT_DEBUG("Format date and timestamp!\n");

    time_t current_time;
    time(&current_time);
    struct tm* time_tm = gmtime(&current_time);
    
    int32_t length = sprintf(ctx->date_buffer, S3_HLS_DATE_FORMAT, time_tm->tm_year + 1900, time_tm->tm_mon + 1, time_tm->tm_mday);
    if(0 >= length)
        return S3_HLS_UNKNOWN_INTERNAL_ERROR;
        
    length = sprintf(ctx->timestamp_buffer, S3_HLS_TIMESTAMP_HEADER_FORMAT, time_tm->tm_year + 1900, time_tm->tm_mon + 1, time_tm->tm_mday, time_tm->tm_hour, time_tm->tm_min, time_tm->tm_sec);
    if(0 >= length)
        return S3_HLS_UNKNOWN_INTERNAL_ERROR;
        
    PUT_DEBUG("Get Content Hash\n");

    S3_SHA256_CTX sha256_ctx;
    S3_SHA256_Init(&sha256_ctx);
    S3_SHA256_Update(&sha256_ctx, first_data, first_length);
    if(NULL != second_data)
        S3_SHA256_Update(&sha256_ctx, second_data, second_length);

    S3_SHA256_HASH payload_hash;
    S3_SHA256_Final(&sha256_ctx, payload_hash);
    
    char payload_hash_string[S3_HLS_HEX_HASH_STIRNG_LENGTH + 1];
    for(uint8_t i = 0; i < sizeof(payload_hash); i++) {
        if(0 >= sprintf(payload_hash_string + (i * 2), "%02x", payload_hash[i]))
            return S3_HLS_UNKNOWN_INTERNAL_ERROR;
    }
    
    payload_hash_string[S3_HLS_HEX_HASH_STIRNG_LENGTH] = '\0';

    PUT_DEBUG("Generate content_hash header!\n");
    if(0 >= sprintf(ctx->content_hash, S3_HLS_CONTENT_SHA256_HEADER_FORMAT, payload_hash_string))
        return S3_HLS_UNKNOWN_INTERNAL_ERROR;

    S3_SHA256_HASH canonical_hash;
    S3_HLS_Hash_Put_Canonical_Request(ctx, object_key, canonical_hash);

    char canonical_hash_string[S3_HLS_HEX_HASH_STIRNG_LENGTH + 1];
    for(uint8_t i = 0; i < S3_SHA256_DIGEST_LENGTH; i++) {
        if(0 >= sprintf(canonical_hash_string + (i * 2), "%02x", canonical_hash[i])) {
            return S3_HLS_UNKNOWN_INTERNAL_ERROR;
        }
    }
    
    canonical_hash_string[S3_HLS_HEX_HASH_STIRNG_LENGTH] = '\0'; // add null terminator

    if(0 >= sprintf(    ctx->string_to_sign,
                        S3_HLS_STRING_TO_SIGN_FORMAT,
                        ctx->timestamp_buffer + S3_HLS_TIMESTAMP_VALUE_OFFSET,
                        ctx->date_buffer,
                        ctx->region,
                        canonical_hash_string
                    )) {
        return S3_HLS_UNKNOWN_INTERNAL_ERROR;
    }
    
    if(0 != pthread_mutex_lock(&ctx->credential_lock))
        return S3_HLS_LOCK_FAILED;

    S3_SHA256_HASH date_key;
    S3_HMAC_SHA256(
                    ctx->secret_access_key, 
                    strlen(ctx->secret_access_key),
                    ctx->date_buffer,
                    strlen(ctx->date_buffer),
                    date_key
                    );

    S3_SHA256_HASH region_key;
    S3_HMAC_SHA256(date_key, SHA256_DIGEST_LENGTH, ctx->region, strlen(ctx->region), region_key);

    S3_SHA256_HASH service_key;
    S3_HMAC_SHA256(region_key, SHA256_DIGEST_LENGTH, S3_SERVICE_KEY, strlen(S3_SERVICE_KEY), service_key);

    S3_SHA256_HASH signing_key;
    S3_HMAC_SHA256(service_key, SHA256_DIGEST_LENGTH, AWS_SIGV4_REQUEST, strlen(AWS_SIGV4_REQUEST), signing_key);

    PUT_DEBUG("String To Sign: \n%s\n", ctx->string_to_sign);
    S3_SHA256_HASH signature;
    S3_HMAC_SHA256(signing_key, SHA256_DIGEST_LENGTH, ctx->string_to_sign, strlen(ctx->string_to_sign), signature);

    char signature_hash_string[S3_HLS_HEX_HASH_STIRNG_LENGTH + 1];
    for(uint8_t i = 0; i < S3_SHA256_DIGEST_LENGTH; i++) {
        if(0 >= sprintf(signature_hash_string + (i * 2), "%02x", signature[i])) {
            pthread_mutex_unlock(&ctx->credential_lock);
            return S3_HLS_UNKNOWN_INTERNAL_ERROR;
        }
    }
    
    signature_hash_string[S3_HLS_HEX_HASH_STIRNG_LENGTH] = '\0';
    
    PUT_DEBUG("String signed!\n");
    PUT_DEBUG("Auth header address: %ld!\n", ctx->auth_header);
    length = sprintf(
                        ctx->auth_header,
                        S3_HLS_AUTHENTICATION_HEADER_FORMAT,
                        ctx->access_key,
                        ctx->date_buffer,
                        ctx->region,
                        NULL != ctx->token_header ? S3_HLS_TOKEN_HEADER_IN_CANONICAL_REQUEST : S3_HLS_EMPTY_STRING,
                        NULL == ctx->tag_header ? S3_HLS_EMPTY_STRING : S3_HLS_TAG_HEADER_IN_CANONICAL_REQUEST,
                        signature_hash_string
                    );

    pthread_mutex_unlock(&ctx->credential_lock);
    
    if(0 >= length)
        return S3_HLS_UNKNOWN_INTERNAL_ERROR;

    PUT_DEBUG("Auth header: \n%s\n", ctx->auth_header);

    length = sprintf(ctx->uri, S3_HLS_HTTPS_URI_FORMAT, ctx->endpoint, object_key);
    if(0 >= length)
        return S3_HLS_UNKNOWN_INTERNAL_ERROR;

    /* get a curl handle */
    printf("Start Upload!\n");
    if(NULL == ctx->curl) {
l_retry_entry:
        ctx->curl = curl_easy_init();
        if(NULL == ctx->curl) {
            fprintf(stderr, "curl_easy_init() failed!\n");
            
            return S3_HLS_HTTP_CLIENT_INIT_ERROR;
        }
        
        curl_easy_setopt(ctx->curl, CURLOPT_READFUNCTION, S3_HLS_Upload_Data);
    }

    S3_HLS_UPLOAD_CTX upload_ctx;
    upload_ctx.first_part_start = first_data;
    upload_ctx.first_part_length = first_length;
    
    upload_ctx.second_part_start = second_data;
    upload_ctx.second_part_length = second_length;
    
    upload_ctx.pos = 0;

    // adding headers
    struct curl_slist *headers = NULL;

    // set upload methods
    curl_easy_setopt(ctx->curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(ctx->curl, CURLOPT_PUT, 1L);
    
    /* First set the URL that is about to receive our POST. */ 
    curl_easy_setopt(ctx->curl, CURLOPT_URL, ctx->uri);

    PUT_DEBUG("Upload CTX: %ld\n", &upload_ctx);
    curl_easy_setopt(ctx->curl, CURLOPT_READDATA, &upload_ctx);

    uint32_t payload_length = first_length + second_length;
    curl_easy_setopt(ctx->curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)payload_length);

    /* enable TCP keep-alive for this transfer */
    curl_easy_setopt(ctx->curl, CURLOPT_TCP_KEEPALIVE, 1L);
    /* keep-alive idle time to 120 seconds */
    curl_easy_setopt(ctx->curl, CURLOPT_TCP_KEEPIDLE, 180L);
    /* interval time between keep-alive probes: 60 seconds */
    curl_easy_setopt(ctx->curl, CURLOPT_TCP_KEEPINTVL, 60L);
    
    curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT, S3_HLS_CURL_TRANSFER_TIMEOUT);

    curl_easy_setopt(ctx->curl, CURLOPT_CONNECTTIMEOUT, S3_HLS_CURL_CONNECTION_TIMEOUT);

    curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYSTATUS, 0);     
    curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, 0);
    
    headers = curl_slist_append(headers, ctx->content_hash);
    headers = curl_slist_append(headers, ctx->timestamp_buffer);
    headers = curl_slist_append(headers, "Expect:");
    headers = curl_slist_append(headers, "Accept:");

    if(NULL != ctx->token_header) {
        headers = curl_slist_append(headers, ctx->token_header);
    }
    
    if(NULL != ctx->tag_header) {
        headers = curl_slist_append(headers, ctx->tag_header);
    }

    PUT_DEBUG("Auth Header: %s\n", ctx->auth_header);
    headers = curl_slist_append(headers, ctx->auth_header);

    /* Now specify we want to POST data */ 
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);
    
    /* get verbose debug output please */ 
    curl_easy_setopt(ctx->curl, CURLOPT_VERBOSE, 1L);
    
    PUT_DEBUG("Start Put!\n");
    /* Perform the request, res will get the return code */ 
    CURLcode res = curl_easy_perform(ctx->curl);
    PUT_DEBUG("Put Done!\n");
    
    curl_slist_free_all(headers);

    /* Check for errors */ 
    if(res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    
        printf("Error, clean up curl!\n");
        curl_easy_cleanup(ctx->curl);
        
        ctx->curl = NULL;
        printf("Curl cleaned!\n");
        
        if(!retry_flag) {
            retry_flag = 1;
            goto l_retry_entry;
        }
        
        return S3_HLS_UPLOAD_FAILED;
    }

    return S3_HLS_OK;
}

int32_t S3_HLS_Client_Upload_Object(S3_HLS_CLIENT_CTX* ctx, char* object_key, uint8_t* data, uint32_t length) {
    return S3_HLS_Client_Upload_Buffer(ctx, object_key, data, length, NULL, 0);
}
