BUILD=release

prefix=/usr/local
exec_prefix=${prefix}

LIBDIR=${exec_prefix}/lib
INCDIR=${prefix}/include/dssl

OBJ_PATH=./${BUILD}
OUT_PATH=./${BUILD}

CFLAGS_debug=-g
CC=gcc
CFLAGS=-c ${CFLAGS_${BUILD}}
AR=ar -cvq
INSTALL=/usr/bin/install -c
INSTALL_DATA=${INSTALL} -m 644

SRC = capture_env.c ciphersuites.c decoder.c \
	decoder_stack.c fnv_hash.c ip_decode.c \
	log.c packet.c pcap_decode.c session.c \
	session_table.c ssl_ctx.c ssl_decode.c \
	ssl_decode_hs.c ssl_mac.c ssl_session.c \
	ssl_sessionkey_table.c ssl_utils.c stream.c \
	tcp_decode.c

INST_HDR = sslcap.h ptypes.h dssl_defs.h log.h \
	errors.h capenv.h session_table.h session.h \
	stream.h packet.h ssl_ctx.h 

OBJ = ${SRC:.c=.o}
OBJS = ${OBJ:%.o=${OBJ_PATH}/%.o}
LIB_OUT=${OUT_PATH}/libdssl.a


${OBJ_PATH}/%.o: %.c
	@mkdir -p ${OBJ_PATH}
	${CC} ${CFLAGS} -o $@ $<

${LIB_OUT}: ${OBJS}
	@mkdir -p ${OUT_PATH}
	${AR} $@  ${OBJS}

all:	${LIB_OUT}

clean:
	rm -rf ${OBJS} ${LIB_OUT}

install: ${LIB_OUT}
	./mkinstalldirs ${LIBDIR} 
	./mkinstalldirs ${INCDIR}
	${INSTALL_DATA} ${LIB_OUT} ${LIBDIR}/libdssl.a
	${foreach hdr, ${INST_HDR}, ${INSTALL_DATA} ${hdr} ${INCDIR}/${hdr};}

uninstall:
	rm -rf ${INCDIR}
	rm -f ${LIBDIR}/libdssl.a

test:	${LIB_OUT}
	@${MAKE} -C tests all test  BUILD=${BUILD}
