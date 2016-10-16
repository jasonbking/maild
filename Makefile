CC=/opt/gcc-4.4.4/bin/gcc

CFLAGS = -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -D__EXTENSIONS__ \
	 -D_FILE_OFFSET_BITS=64
CFLAGS += -std=c99
CFLAGS += -g

LDFLAGS = -lnvpair

SRCS = signal.c local.c log.c privcmd.c nvdoor.c client.c aliases.c \
       util.c server.c maild.c msg.c

OBJS = $(SRCS:%.c=%.o)
PROG = maild

maild: $(OBJS)
	$(CC) $(CFLAGS) -o maild $(OBJS) $(LDFLAGS)

include Makefile.dep

depend:
	$(CC) $(CFLAGS) -MM $(SRCS) > Makefile.dep

clean:
	rm -f $(OBJS) $(PROG)
