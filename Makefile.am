## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include

libdir = ${exec_prefix}/lib/snort_dynamicpreprocessor

lib_LTLIBRARIES = libsf_ssl_preproc.la

libsf_ssl_preproc_la_LDFLAGS = -module

BUILT_SOURCES = \
sf_dynamic_preproc_lib.c 

nodist_libsf_ssl_preproc_la_SOURCES = \
sf_dynamic_preproc_lib.c

libsf_ssl_preproc_la_SOURCES = \
callbacks.c  callbacks.h  load_config.c  pkt_utils.c \
pkt_utils.h  sf_preproc_info.h  spp_ssl.c  spp_ssl.h  \
pkt_utils_s.c sf_preproc_info.h

EXTRA_DIST = \
sf_ssl.vcproj

sf_dynamic_preproc_lib.c: ../include/sf_dynamic_preproc_lib.c
	cp $? $@

all-local:
        $(MAKE) DESTDIR=$(PWD)/../build install-libLTLIBRARIES

clean-local:
	rm -f sf_dynamic_preproc_lib.c
