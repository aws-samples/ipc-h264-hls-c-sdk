VERSION=v2.4

CROSS_COMPILE=
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
AR=$(CROSS_COMPILE)ar

SODEF_yes=-fPIC

DEF=-DRTMPDUMP_VERSION=\"$(VERSION)\" #$(CRYPTO_DEF) $(XDEF)
OPT=-O2
CFLAGS=-Wall $(XCFLAGS) $(INC) $(DEF) $(OPT) $(SO_DEF) 
SO_LDFLAGS=-shared -Wl,-soname,
LDFLAGS=$(XLDFLAGS)

OBJS=s3_hls_sdk.o s3_simple_put.o s3_crypto.o
all:	static

clean:
	rm -f *.o *.a *.so *.so.1

static: $(OBJS)
	$(AR) rs s3_hls.a $?

dynamic: $(OBJS)
	$(CC) $(SO_LDFLAGS) $(LDFLAGS) -o s3_hls.so.1 $^

s3_hls_sdk.o:  ./S3_HLS_SDK.c ./S3_HLS_SDK.h
	$(CC) $(CFLAGS) -I./ -I./3rd/openssl/include -c -o s3_hls_sdk.o ./S3_HLS_SDK.c

s3_simple_put.o: ./S3_Simple_Put.c ./S3_Simple_Put.h
	$(CC) $(CFLAGS) -I./ -I/usr/local/include -I./3rd/openssl/include -c -o s3_simple_put.o ./S3_Simple_Put.c

s3_crypto.o: ./S3_Crypto.c ./S3_Crypto.h
	$(CC) $(CFLAGS) -I./ -I/usr/local/include -I./3rd/openssl/include -c -o s3_crypto.o ./S3_Crypto.c

