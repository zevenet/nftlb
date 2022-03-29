include Make_global.am

ACLOCAL_AMFLAGS	= -I m4

man_MANS = nftlb.8
EXTRA_DIST = include	\
	     tests	\
             $(man_MANS) \
	     Make_global.am

SUBDIRS		= src
DIST_SUBDIRS	= src
LIBS = @LIBNFTABLES_LIBS@ @LIBJSON_LIBS@ @LIBMNL_LIBS@
