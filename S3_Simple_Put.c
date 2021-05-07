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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>

#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"

#include "S3_Simple_Put.h"
#include "S3_Crypto.h"

#define DEBUG_HLS_PUT

#ifdef DEBUG_HLS_PUT
#define DEBUG_PRINT(x, ...) printf(x,## __VA_ARGS__)
#else
#define DEBUG_PRINT(x, ...)
#endif

#define BIT_PER_BYTE			8

// Uncomment below line if you want to use CURL library
//#define USE_CURL

// Uncomment below line if you want to use HTTPS endpoints
// Use HTTPS endpoints MUST use CURL library!
//#define HTTPS

#ifdef USE_CURL
#include <curl/curl.h>
#endif

#define S3_SERVICE_KEY                      "s3"
#define AWS_SIGV4_REQUEST                   "aws4_request"

#define S3_PUT_ENDPOINT_FORMAT              "%s.s3.%s.amazonaws.com%s"
#define S3_PUT_CONTENT_LENGTH_FORMAT        "%d"

// timestamp, date, region, canonical hash
#define S3_PUT_STRING_TO_SIGN_FORMAT        "AWS4-HMAC-SHA256\n%s\n%s/%s/s3/aws4_request\n%s"

// ak, date, region, signature
#define S3_PUT_AUTHORIZATION_HEADER_FORMAT  "AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request,SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date%s,Signature=%s"

#define HTTP_VERSION            "HTTP/1.1"

typedef struct http_header_s {
    char* name;
    char* value;
    struct http_header_s* next;
} http_header;

typedef struct http_request_s {
    char* method;
    char* path;
    
    struct http_header_s* first_header;
    
    unsigned char* payload;
    unsigned int payload_size;
} http_request;

static char* m_ak = NULL;
static char* m_sk = NULL;
static char* m_region = NULL;
static char* m_bucket = NULL;
static char* m_prefix = NULL;
static char* m_endpoint = NULL;
static char* m_token = NULL;

void S3_Put_Initialize(char* ak, char* sk, char* token, char* region, char* bucket, char* prefix) {
    m_ak = ak;
    m_sk = sk;
    m_token = token;
    m_region = region;
    m_bucket = bucket;
    m_prefix = prefix;
    
    // add endpoint here
    const char* postfix = "";
    if(m_region) {
        if('c' == *m_region) {
            if('n' == *(m_region+1)) {
                postfix = ".cn";
            }
        }
        
        int length = snprintf(NULL, 0, S3_PUT_ENDPOINT_FORMAT, m_bucket, m_region, postfix);
        if(length >= 0) {
            length++;
            m_endpoint = (char*)malloc(length);
            if(m_endpoint)
                snprintf(m_endpoint, length, S3_PUT_ENDPOINT_FORMAT, m_bucket, m_region, postfix);
        }
    }
    
    DEBUG_PRINT("m_ak        %s\n", m_ak);
    DEBUG_PRINT("m_sk        %s\n", m_sk);
    DEBUG_PRINT("m_region:   %s\n", m_region);
    DEBUG_PRINT("m_bucket:   %s\n", m_bucket);
    DEBUG_PRINT("m_prefix:   %s\n", m_prefix);
    DEBUG_PRINT("m_endpoint: %s\n", m_endpoint);
}

void S3_Put_Finalize() {
    if(m_endpoint)
        free(m_endpoint);
}

char* S3_PUT_Generate_Canonical_Request(http_request* req, char* object_key, char* payload_hash) {
    DEBUG_PRINT("S3_PUT_Generate_Canonical_Request\n");

    int length = 0;
    if(m_prefix)
        length += snprintf(NULL, 0, "PUT\n%s%s\n\n", m_prefix, object_key);
    else
        length += snprintf(NULL, 0, "PUT\n%s\n\n", object_key);
    
    http_header* header = req->first_header;
    while(header) {
        length += snprintf(NULL, 0, "%s:%s\n", header->name, header->value); // name:value\n
        length += snprintf(NULL, 0, "%s;", header->name);//signed headers
        
        header = header->next;
    }
    
    // will replace last ';' with '\n', length not changed
    
    // will add additional '\n' after headers
    length++; 
    
    length += snprintf(NULL, 0, "%s", payload_hash);
    
    length++;
    
    char* request_string = (char*)malloc(length);
    if(!request_string)
        return NULL;
    
    DEBUG_PRINT("Total length: %d\n", length);

    int cur_pos = 0;
    int temp_length;

    DEBUG_PRINT("generate request string\n");

    if(m_prefix)
        temp_length = snprintf(request_string + cur_pos, length - cur_pos, "PUT\n%s%s\n\n", m_prefix, object_key);
    else
        temp_length = snprintf(request_string + cur_pos, length - cur_pos, "PUT\n%s\n\n", object_key);
    
    if(0 >= temp_length) 
        goto l_error;

    cur_pos += temp_length;

    DEBUG_PRINT("Adding headers\n");

    header = req->first_header;
    while(header) {
        temp_length = snprintf(request_string + cur_pos, length - cur_pos, "%s:%s\n", header->name, header->value); // name:value\n
        
        if(0 >= temp_length) 
            goto l_error;
        
        cur_pos += temp_length;
        header = header->next;
    }
    
    DEBUG_PRINT("Adding additional \\n\n");

    *(request_string + cur_pos) = '\n';
    cur_pos++;

    DEBUG_PRINT("generate signed headers\n");

    header = req->first_header;
    while(header) {
        temp_length = snprintf(request_string + cur_pos, length - cur_pos, "%s;", header->name); // name:value\n
        
        if(0 >= temp_length) 
            goto l_error;
        
        cur_pos += temp_length;
        header = header->next;
    }
    
    *(request_string + cur_pos - 1) = '\n';
    
    DEBUG_PRINT("Adding hash\n");

    temp_length = snprintf(request_string + cur_pos, length - cur_pos, "%s", payload_hash);
    if(0 >= temp_length) 
        goto l_error;
        
    cur_pos += temp_length;
    
    *(request_string + cur_pos) = '\0';

    return request_string;
    
l_error:
    free(request_string);
    return NULL;
}

#ifdef USE_CURL

typedef struct put_header_list_s {
    char* header;
    struct put_header_list_s* next;
} put_header_list;

int S3_Put_Send_Request(http_request* req) {
  CURL *curl;
  CURLcode res;
 
  put_header_list *header_list = NULL;
  // adding headers
  struct curl_slist *headers = NULL;
 
  /* In windows, this will init the winsock stuff */ 
  res = curl_global_init(CURL_GLOBAL_DEFAULT);
  /* Check for errors */ 
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed: %s\n",
            curl_easy_strerror(res));
    return 1;
  }
 
  /* get a curl handle */ 
  curl = curl_easy_init();
  if(curl) {
    /* First set the URL that is about to receive our POST. */ 
#ifdef HTTPS
    int length = snprintf(NULL, 0, "https://%s%s", m_endpoint, req->path);
#else
    int length = snprintf(NULL, 0, "http://%s%s", m_endpoint, req->path);
#endif
    length++;
    char* url = (char*)malloc(length);
    if(NULL == url)
        goto l_curl_clean;
        
#ifdef HTTPS
    length = snprintf(url, length, "https://%s%s", m_endpoint, req->path);
#else
    length = snprintf(url, length, "http://%s%s", m_endpoint, req->path);
#endif

    url[length] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    
    /* enable TCP keep-alive for this transfer */
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    /* keep-alive idle time to 120 seconds */
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 180L);
    /* interval time between keep-alive probes: 60 seconds */
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 60L);
  
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT"); /* !!! */

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->payload); /* data goes here */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, req->payload_size);

#ifdef HTTPS    
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 0);     
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
#endif

    http_header* h = req->first_header;
    while(h) {
        length = snprintf(NULL, 0, "%s:%s", h->name, h->value);
        if(0 >= length) 
            goto l_failed;
        
        length++;
        put_header_list* header_item = (put_header_list*)malloc(sizeof(put_header_list));
        if(!h)
            goto l_clean_header;
        
        header_item->next = header_list;
        header_list = header_item;

        header_item->header = (char*)malloc(length);
        
        if(!header_item->header)
            goto l_clean_header;
        
        length = snprintf(header_item->header, length, "%s:%s", h->name, h->value);
        if(0 >= length)
            goto l_clean_header;
            
        headers = curl_slist_append(headers, header_item->header);
        h = h->next;
    }

    /* Now specify we want to POST data */ 
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* get verbose debug output please */ 
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* Perform the request, res will get the return code */ 
    res = curl_easy_perform(curl);
    /* Check for errors */ 
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

l_curl_clean: 
    /* always cleanup */ 
    curl_slist_free_all(headers);
    
    curl_easy_cleanup(curl);
  }
  
  curl_global_cleanup();
  
  return 0;
  
l_clean_header:
    while(header_list) {
        put_header_list* temp = header_list->next;
        
        if(!header_list->header) {
            if(0 != strcmp(header_list->header, "transfer-encoding:identity")) {
                free(header_list->header);
                header_list->header = NULL;
            }
        }
        
        free(header_list);
        header_list = temp;
    }
  
l_failed:
    /* always cleanup */ 
    curl_slist_free_all(headers);
    
    curl_easy_cleanup(curl);

    curl_global_cleanup();
    
    return 1;
}
#else
int S3_Put_Send_Request(http_request* req) {
    DEBUG_PRINT("S3_Put_Send_Request\n");

    struct addrinfo *info, *rp;
    
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    int tmpSfd = -1;
    
    // Get address information from host, port information and because HTTP is a TCP protocol, so specify for SOCK_STREAM
    if(0 != getaddrinfo(m_endpoint, "http", &hints, &info)) // get the address from host name or ip string
        return S3_SIMPLE_PUT_CREATE_SOCKET_FAILED;

    // Successfully get address information, transverse all returned addresses
    rp = info;
    int j = 0;
    while (NULL != rp) { 
        tmpSfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(0 <= tmpSfd) {
            if(0 == connect(tmpSfd, rp->ai_addr, rp->ai_addrlen)) {
                break;
            } else { // failed to connect try another connection descriptor
                close(tmpSfd);
                tmpSfd = -1;
            }
        }
        j++;
    
        rp = rp->ai_next;
    }// transverse returend addresses
    
    freeaddrinfo(info);
    
    if(-1 == tmpSfd) { // failed to create connection
        return S3_SIMPLE_PUT_CONNECT_FAILED;
    }

    int ret = send(tmpSfd, req->method, strlen(req->method) , 0);
    if(0 > ret) {
        close(tmpSfd);
        return S3_SIMPLE_PUT_SEND_DATA_FAILED;
    }
    
    DEBUG_PRINT("%s", req->method);
    ret = send(tmpSfd, " ", 1 , 0);
    if(0 > ret) {
        close(tmpSfd);
        return S3_SIMPLE_PUT_SEND_DATA_FAILED;
    }

    DEBUG_PRINT(" ");
    ret = send(tmpSfd, req->path, strlen(req->path) , 0);
    if(0 > ret) {
        close(tmpSfd);
        return S3_SIMPLE_PUT_SEND_DATA_FAILED;
    }

    DEBUG_PRINT("%s", req->path);
    ret = send(tmpSfd, " ", 1 , 0);
    if(0 > ret) {
        close(tmpSfd);
        return S3_SIMPLE_PUT_SEND_DATA_FAILED;
    }

    DEBUG_PRINT(" ");
    ret = send(tmpSfd, HTTP_VERSION, strlen(HTTP_VERSION) , 0);
    if(0 > ret) {
        close(tmpSfd);
        return S3_SIMPLE_PUT_SEND_DATA_FAILED;
    }

    DEBUG_PRINT("%s", HTTP_VERSION);
    ret = send(tmpSfd, "\n", 1 , 0);
    if(0 > ret) {
        close(tmpSfd);
        return S3_SIMPLE_PUT_SEND_DATA_FAILED;
    }

    DEBUG_PRINT("\n");

    http_header* header = req->first_header;
    while(NULL != header) {
        send(tmpSfd, header->name, strlen(header->name) , 0);
        if(0 > ret) {
            close(tmpSfd);
            return S3_SIMPLE_PUT_SEND_DATA_FAILED;
        }

        DEBUG_PRINT("%s",header->name);
        send(tmpSfd, ":", 1 , 0);
        if(0 > ret) {
            close(tmpSfd);
            return S3_SIMPLE_PUT_SEND_DATA_FAILED;
        }
        
        DEBUG_PRINT(":");
        send(tmpSfd, header->value, strlen(header->value) , 0);
        if(0 > ret) {
            close(tmpSfd);
            return S3_SIMPLE_PUT_SEND_DATA_FAILED;
        }
        
        DEBUG_PRINT("%s",header->value);
        send(tmpSfd, "\n", 1 , 0);
        if(0 > ret) {
            close(tmpSfd);
            return S3_SIMPLE_PUT_SEND_DATA_FAILED;
        }

        DEBUG_PRINT("\n");
        header = header->next;
    }

    send(tmpSfd, "\n", 1 , 0);
    if(0 > ret) {
        close(tmpSfd);
        return S3_SIMPLE_PUT_SEND_DATA_FAILED;
    }

    DEBUG_PRINT("\n");
    
    if(NULL != req->payload && 0 != req->payload_size) {
        send(tmpSfd, req->payload, req->payload_size , 0);
        if(0 > ret) {
            close(tmpSfd);
            return S3_SIMPLE_PUT_SEND_DATA_FAILED;
        }
    }

    char buff;
    char last = '\0';

    DEBUG_PRINT("Received: \n");

    while(0 < recv(tmpSfd, &buff, 1, 0)) {
        DEBUG_PRINT("%c", buff);

        if('\n' == last && '\n' == buff) {
            break;
        }
        if('\r' != buff) {
            last = buff;
        }
    }
    
    DEBUG_PRINT("Complete!\n");

    close(tmpSfd);

    return 0;
}
#endif

int S3_Put_Object(char* object_key, unsigned char* payload, unsigned int size) {
    DEBUG_PRINT("S3_Put_Send_Request\n");

    int ret = S3_SIMPLE_PUT_OK;
    
    http_request req;
    req.method = "PUT";
    req.payload = payload;
    req.payload_size = size;

    int length;
    if(m_prefix) {
        length = snprintf(NULL, 0, "%s%s", m_prefix, object_key);
        if(0 >= length) 
            return S3_SIMPLE_RUNTIME_ERROR;
        
        length++;
        req.path = (char*)malloc(length);
        if(!req.path)
            return S3_SIMPLE_PUT_NOT_ENOUGHT_MEMORY;
            
        length = snprintf(req.path, length, "%s%s", m_prefix, object_key);
        if(0 >= length) {
            ret = S3_SIMPLE_RUNTIME_ERROR;
            goto l_free_path;
        }
    } else {
        req.path = object_key; 
    }

    
    // initialize headers
    DEBUG_PRINT("initialize headers\n");
    http_header content_length_header;
    req.first_header = &content_length_header;
    
    DEBUG_PRINT("initialize content length header\n");

    content_length_header.name = "content-length";
    
    length = snprintf(NULL, 0, S3_PUT_CONTENT_LENGTH_FORMAT, size);
    if(0 >= length) {
        ret = S3_SIMPLE_PUT_NOT_ENOUGHT_MEMORY;
        goto l_free_path;
    }
    
    length++;
    
    content_length_header.value = (char*)malloc(length);
    if(NULL == content_length_header.value) {
        ret = S3_SIMPLE_PUT_NOT_ENOUGHT_MEMORY;
        goto l_free_path;
    }

    length = snprintf(content_length_header.value, length, S3_PUT_CONTENT_LENGTH_FORMAT, size);
    if(0 >= length) {
        ret = S3_SIMPLE_RUNTIME_ERROR;
        goto l_free_content_length;
    }

    DEBUG_PRINT("initialize host header\n");
    
    http_header host_header;
    content_length_header.next = &host_header;

    host_header.name = "host";
    host_header.value = m_endpoint;
    
    DEBUG_PRINT("initialize content hash header\n");

    // each bytes will be convert to 2 character with an additional 1 NULL terminator
    char content_hash[SHA256_DIGEST_LENGTH*2+1];
    http_header content_hash_header;
    host_header.next = &content_hash_header;
    content_hash_header.name = "x-amz-content-sha256";
    content_hash_header.value = content_hash;
    
    // hash payload
    unsigned char dataHash[SHA256_DIGEST_LENGTH];
    S3_SHA256((char*)req.payload, req.payload_size, dataHash);
    
    unsigned char chlength = 0;
    while(chlength < SHA256_DIGEST_LENGTH) {
        length = snprintf(content_hash + (2 * chlength), SHA256_DIGEST_LENGTH * 2 + 1 - (2 * chlength), "%02x", dataHash[chlength] & 0xFF);
        if(0 >= length) {
            ret = S3_SIMPLE_RUNTIME_ERROR;
            goto l_free_content_length;
        }
        
        chlength ++;
    }
    
    content_hash[2*chlength] = '\0';
    
    DEBUG_PRINT("initialize date header\n");

    char date_time[17] = {0};
    http_header date_header;
    content_hash_header.next = &date_header;
    date_header.next = NULL;
    date_header.name = "x-amz-date";
    date_header.value = date_time;
    
    DEBUG_PRINT("initialize security token header\n");

    http_header token_header;
    token_header.next = NULL;
    token_header.name = "x-amz-security-token";
    token_header.value = m_token;
    if(NULL != token_header.value) {
        date_header.next = &token_header;
    }

    time_t rawtime;
    time(&rawtime);
    struct tm* tm = gmtime( &rawtime );

    length = snprintf(date_time, 17, "%04d%02d%02dT%02d%02d%02dZ", tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    if(0 >= length) {
        ret = S3_SIMPLE_RUNTIME_ERROR;
        goto l_free_content_length;
    }
    
    char date[9] = {0};
    length = snprintf(date, 9, "%04d%02d%02d", tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday);
    if(0 >= length) {
        ret = S3_SIMPLE_RUNTIME_ERROR;
        goto l_free_content_length;
    }
    
    int sk_length = strlen(m_sk);
    sk_length += 5;
    char* tempSK = (char*)malloc(sk_length);
    if(NULL == tempSK) {
        ret = S3_SIMPLE_PUT_NOT_ENOUGHT_MEMORY;
        goto l_free_content_length;
    }
    
    length = snprintf(tempSK, sk_length, "AWS4%s", m_sk);
    if(0 >= length) {
        ret = S3_SIMPLE_RUNTIME_ERROR;
        goto l_free_tempSK;
    }
    
    DEBUG_PRINT("Generate signing key\n");

    unsigned char dateKey[SHA256_DIGEST_LENGTH];
    S3_HMAC_SHA256((unsigned char*)tempSK, sk_length, date, strlen(date), dateKey, SHA256_DIGEST_LENGTH);

    unsigned char regionKey[SHA256_DIGEST_LENGTH];
    S3_HMAC_SHA256(dateKey, SHA256_DIGEST_LENGTH, m_region, strlen(m_region), regionKey, SHA256_DIGEST_LENGTH);

    unsigned char serviceKey[SHA256_DIGEST_LENGTH];
    S3_HMAC_SHA256(regionKey, SHA256_DIGEST_LENGTH, S3_SERVICE_KEY, strlen(S3_SERVICE_KEY), serviceKey, SHA256_DIGEST_LENGTH);
    
    unsigned char signingKey[SHA256_DIGEST_LENGTH];
    S3_HMAC_SHA256(serviceKey, SHA256_DIGEST_LENGTH, AWS_SIGV4_REQUEST, strlen(AWS_SIGV4_REQUEST), signingKey, SHA256_DIGEST_LENGTH);

    DEBUG_PRINT("Generate canonical request\n");

    char* canonical_request = S3_PUT_Generate_Canonical_Request(&req, object_key, content_hash);
    if(!canonical_request) {
        ret = S3_SIMPLE_PUT_NOT_ENOUGHT_MEMORY;
        goto l_free_tempSK;
    }
    
    DEBUG_PRINT("canonical_request:\n%s\n", canonical_request);

    unsigned char canonical_hash[SHA256_DIGEST_LENGTH];
    S3_SHA256(canonical_request, strlen(canonical_request), canonical_hash);
    
    free(canonical_request);

    char canonical_request_hash[SHA256_DIGEST_LENGTH*2+1];
    chlength = 0;
    while(chlength < SHA256_DIGEST_LENGTH) {
        length = snprintf(canonical_request_hash + (2 * chlength), SHA256_DIGEST_LENGTH * 2 + 1 - (2 * chlength), "%02x", canonical_hash[chlength] & 0xFF);
        if(0 >= length) {
            ret = S3_SIMPLE_RUNTIME_ERROR;
            goto l_free_tempSK;
        }
        
        chlength ++;
    }
    
    canonical_request_hash[2*chlength] = '\0';

    DEBUG_PRINT("Generate string to sign\n");

    length = snprintf(NULL, 0, S3_PUT_STRING_TO_SIGN_FORMAT, date_time, date, m_region, canonical_request_hash);
    if(0 >= length) {
        ret = S3_SIMPLE_RUNTIME_ERROR;
        goto l_free_tempSK;
    }
    
    length++;
    
    char* string_to_sign = (char*)malloc(length);
    if(!string_to_sign) {
        ret = S3_SIMPLE_PUT_NOT_ENOUGHT_MEMORY;
        goto l_free_tempSK;
    }

    length = snprintf(string_to_sign, length, S3_PUT_STRING_TO_SIGN_FORMAT, date_time, date, m_region, canonical_request_hash);
    if(0 >= length) {
        ret = S3_SIMPLE_RUNTIME_ERROR;
        free(string_to_sign);
        goto l_free_tempSK;
    }
    
    string_to_sign[length] = '\0';

    DEBUG_PRINT("Generate signature\n");

    unsigned char signature[SHA256_DIGEST_LENGTH];
    S3_HMAC_SHA256(signingKey, SHA256_DIGEST_LENGTH, string_to_sign, strlen(string_to_sign), signature, SHA256_DIGEST_LENGTH);
    
    free(string_to_sign);
    
    char signature_hash[SHA256_DIGEST_LENGTH*2+1];
    chlength = 0;
    while(chlength < SHA256_DIGEST_LENGTH) {
        length = snprintf(signature_hash + (2 * chlength), SHA256_DIGEST_LENGTH * 2 + 1 - (2 * chlength), "%02x", signature[chlength] & 0xFF);
        if(0 >= length) {
            ret = S3_SIMPLE_RUNTIME_ERROR;
            goto l_free_tempSK;
        }
        
        chlength ++;
    }
    
    signature_hash[2*chlength] = '\0';
    
    DEBUG_PRINT("Generate authorization header\n");

    if(NULL == m_token)
        length = snprintf(NULL, 0, S3_PUT_AUTHORIZATION_HEADER_FORMAT, m_ak, date, m_region, "", signature_hash);
    else
        length = snprintf(NULL, 0, S3_PUT_AUTHORIZATION_HEADER_FORMAT, m_ak, date, m_region, ";x-amz-security-token", signature_hash);
    
    if(0 >= length) {
        ret = S3_SIMPLE_RUNTIME_ERROR;
        goto l_free_tempSK;
    }
    
    length++;
    
    char* auth_value = (char*)malloc(length);
    if(!auth_value){
        ret = S3_SIMPLE_PUT_NOT_ENOUGHT_MEMORY;
        goto l_free_tempSK;
    }
    
    if(NULL == m_token)
        length = snprintf(auth_value, length, S3_PUT_AUTHORIZATION_HEADER_FORMAT, m_ak, date, m_region, "", signature_hash);
    else
        length = snprintf(auth_value, length, S3_PUT_AUTHORIZATION_HEADER_FORMAT, m_ak, date, m_region, ";x-amz-security-token", signature_hash);
    
    if(0 >= length) {
        ret = S3_SIMPLE_RUNTIME_ERROR;
        goto l_free_auth_value;
    }
    
    auth_value[length] = '\0';

    http_header auth_header;
    if(NULL == m_token)
        date_header.next = &auth_header;
    else
        token_header.next = &auth_header;
        
    auth_header.next = NULL;
    auth_header.name = "Authorization";
    auth_header.value = auth_value;
    
    // send
    DEBUG_PRINT("Send request\n");

    S3_Put_Send_Request(&req);

l_free_auth_value:
    free(auth_value);
    
l_free_tempSK:
    free(tempSK);

l_free_content_length:
    free(content_length_header.value);
    
l_free_path:
    if(m_prefix)
        free(req.path);
    
    return ret;
}
