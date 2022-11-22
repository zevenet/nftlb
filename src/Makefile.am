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
		server.c	\
		policies.c	\
		elements.c	\
		farmpolicy.c \
		sessions.c	\
		checksum.c	\
		addresses.c \
		farmaddress.c \
		addresspolicy.c \
		nftst.c \
		../zcutils/src/zcu_backtrace.c \
		../zcutils/src/zcu_log.c \
		../zcutils/src/zcu_network.c \
		../zcutils/src/zcu_sbuffer.c \
		../zcutils/src/zcu_string.c
nftlb_LDADD = ${LIBNFTABLES_LIBS} ${LIBJSON_LIBS} ${LIBMNL_LIBS} -lev
