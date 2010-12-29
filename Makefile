PROG = chmdump

SRCS = chmdump.c chmlib.c lzx.c

CFLAGS = -g -Wall -DDEBUG

NO_MAN =

.include <bsd.prog.mk>
