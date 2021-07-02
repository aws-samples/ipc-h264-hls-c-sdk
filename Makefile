VERSION=v2.4

CROSS_COMPILE=
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
AR=$(CROSS_COMPILE)ar

SODEF_yes=-fPIC

INC=-I./ -I./3rd/openssl/include -I./3rd/curl/include

DEF=-DRTMPDUMP_VERSION=\"$(VERSION)\" #$(CRYPTO_DEF) $(XDEF)
OPT=-O2
CFLAGS=-Wall $(XCFLAGS) $(INC) $(DEF) $(OPT) $(SO_DEF) 
SO_LDFLAGS=-shared -Wl,-soname,
LDFLAGS=$(XLDFLAGS)

OBJS=s3_crypto.o s3_hls_buffer_mgr.o s3_hls_h264_nalu_types.o s3_hls_pat.o s3_hls_pes.o s3_hls_pmt.o s3_hls_queue.o s3_hls_return_code.o s3_hls_s3_put_client.o s3_hls_sdk.o s3_hls_ts.o s3_hls_upload_thread.o
all:	static

clean:
	rm -f *.o *.a *.so *.so.1

static: $(OBJS)
	$(AR) rs s3_hls.a $?

dynamic: $(OBJS)
	$(CC) $(SO_LDFLAGS) $(LDFLAGS) -o s3_hls.so.1 $^

s3_crypto.o: ./S3_Crypto.c ./S3_Crypto.h
	$(CC) $(CFLAGS) -c -o s3_crypto.o ./S3_Crypto.c

s3_hls_buffer_mgr.o: ./S3_HLS_Buffer_Mgr.c ./S3_HLS_Buffer_Mgr.h
	$(CC) $(CFLAGS) -c -o s3_hls_buffer_mgr.o ./S3_HLS_Buffer_Mgr.c

s3_hls_h264_nalu_types.o: ./S3_HLS_H264_Nalu_Types.c ./S3_HLS_H264_Nalu_Types.h
	$(CC) $(CFLAGS) -c -o s3_hls_h264_nalu_types.o ./S3_HLS_H264_Nalu_Types.c

s3_hls_pat.o: ./S3_HLS_Pat.c ./S3_HLS_Pat.h
	$(CC) $(CFLAGS) -c -o s3_hls_pat.o ./S3_HLS_Pat.c

s3_hls_pes.o: ./S3_HLS_Pes.c ./S3_HLS_Pes.h
	$(CC) $(CFLAGS) -c -o s3_hls_pes.o ./S3_HLS_Pes.c

s3_hls_pmt.o: ./S3_HLS_Pmt.c ./S3_HLS_Pmt.h
	$(CC) $(CFLAGS) -c -o s3_hls_pmt.o ./S3_HLS_Pmt.c

s3_hls_queue.o: ./S3_HLS_Queue.c ./S3_HLS_Queue.h
	$(CC) $(CFLAGS) -c -o s3_hls_queue.o ./S3_HLS_Queue.c

s3_hls_return_code.o: ./S3_HLS_Return_Code.c ./S3_HLS_Return_Code.h
	$(CC) $(CFLAGS) -c -o s3_hls_return_code.o ./S3_HLS_Return_Code.c

s3_hls_s3_put_client.o: ./S3_HLS_S3_Put_Client.c ./S3_HLS_S3_Put_Client.h
	$(CC) $(CFLAGS) -c -o s3_hls_s3_put_client.o ./S3_HLS_S3_Put_Client.c

s3_hls_sdk.o: ./S3_HLS_SDK.c ./S3_HLS_SDK.h
	$(CC) $(CFLAGS) -c -o s3_hls_sdk.o ./S3_HLS_SDK.c

s3_hls_ts.o: ./S3_HLS_TS.c ./S3_HLS_TS.h
	$(CC) $(CFLAGS) -c -o s3_hls_ts.o ./S3_HLS_TS.c

s3_hls_upload_thread.o: ./S3_HLS_Upload_Thread.c ./S3_HLS_Upload_Thread.h
	$(CC) $(CFLAGS) -c -o s3_hls_upload_thread.o ./S3_HLS_Upload_Thread.c
