include $(top_srcdir)/Make_global.am

sbin_PROGRAMS = nftlb

nftlb_SOURCES = config.c	\
		main.c		\
		model.c		\
		nft.c		\
		events.c	\
		server.c
nftlb_LDADD = ${LIBNFTABLES_LIBS} ${LIBJSON_LIBS}
