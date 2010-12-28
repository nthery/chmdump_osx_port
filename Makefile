LIBOBJS = chmlib.o lzx.o
CFLAGS = -DDEBUG
PROGS = chmdump

chmdump: $(LIBOBJS) chmdump.o
	$(LINK.c) -o $@ $^

clean:
	rm -f *.o *~ \#* core $(PROGS)