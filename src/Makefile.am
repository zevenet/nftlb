include $(top_srcdir)/Make_global.am

sbin_PROGRAMS = nftlb

nftlb_SOURCES = config.c	\
		main.c		\
		objects.c	\
		farms.c		\
		backends.c	\
		nft.c		\
		events.c	\
		network.c	\
		server.c
nftlb_LDADD = ${LIBNFTABLES_LIBS} ${LIBJSON_LIBS} ${LIBMNL_LIBS} -lev
