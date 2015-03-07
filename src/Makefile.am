# what flags you want to pass to the C compiler & linker
AM_CFLAGS = --std=c90 -D_GNU_SOURCE 
AM_LDFLAGS = 

# this lists the binaries to produce, the (non-PHONY, binary) targets in
# the previous manual Makefile
bin_PROGRAMS = igmping
igmping_SOURCES = igmping.c igmping.h igmping_common.c igmping_common.h igmping_socket.c igmping_socket.h igmping_v1.c igmping_v1.h igmping_v2.c igmping_v2.h igmping_v3.c igmping_v3.h
igmping_LDADD = -lrt
