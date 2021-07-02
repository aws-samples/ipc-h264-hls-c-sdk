#ifndef __S3_HLS_RETURN_CODE_H__
#define __S3_HLS_RETURN_CODE_H__

// Return value part
#define S3_HLS_OK                                   0
#define S3_HLS_OUT_OF_MEMORY                        -1
#define S3_HLS_INVALID_PARAMETER                    -2
#define S3_HLS_INVALID_STATUS                       -3
#define S3_HLS_BUFFER_OVERFLOW                      -4
#define S3_HLS_BUFFER_EMPTY                         -5
#define S3_HLS_LOCK_FAILED                          -6
#define S3_HLS_UNKNOWN_INTERNAL_ERROR               -7
#define S3_HLS_QUEUE_FULL                           -8
#define S3_HLS_QUEUE_EMPTY                          -9
#define S3_HLS_HTTP_CLIENT_INIT_ERROR               -10
#define S3_HLS_THREAD_ALREADY_STOPPED               -11
#define S3_HLS_UPLOAD_FAILED                        -12

#define S3_HLS_TS_COUNTER_INDEX                     3

#define S3_HLS_Video_PID                            0x100
#define S3_HLS_Audio_PID                            0x101

#define S3_HLS_TS_PACKET_SIZE                       188

extern char const_fill_word[S3_HLS_TS_PACKET_SIZE];
#endif
