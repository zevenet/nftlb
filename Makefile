IDIR=include
CC=gcc
CFLAGS=-Wall -I$(IDIR) -L../nftables/src/.libs/
ODIR=src
SRCS=main.o server.o config.o model.o nft.o
LIBS=-lev -ljansson -lgmp -lmnl -lnftnl -lnftables
PROG=nftlb

all: $(PROG)

$(PROG) : $(SRCS)
	$(CC) -o $(PROG) $(ODIR)/*.o $(CFLAGS) $(LIBS)

%.o: $(ODIR)/%.c
	$(CC) -c -o $(ODIR)/$@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(PROG) $(ODIR)/*.o *~ $(IDIR)/*~
