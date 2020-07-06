SRCS :=		template.c

CPPFLAGS +=	-DSURICATA_PLUGIN -I.
CPPFLAGS +=	-I../../../src

all:
	$(CC) -fPIC $(CPPFLAGS) -o eve-filetype.so -shared $(SRCS)

clean:
	rm -f *.so *~
