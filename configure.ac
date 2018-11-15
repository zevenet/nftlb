AC_INIT([nftlb], [0.3], [netfilter-devel@vger.kernel.org])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects
        tar-pax no-dist-gzip dist-bzip2 1.6])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_PROG_MKDIR_P
AM_PROG_AR
AM_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_SED

PKG_CHECK_MODULES([LIBNFTABLES], [libnftables >= 0.8.5])
PKG_CHECK_MODULES([LIBJSON], [jansson >= 2.3])
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.4])

AC_CHECK_HEADER([ev.h], [EVENTINC="-include ev.h"],
		[AC_CHECK_HEADER([libev/ev.h],
				 [EVENTINC="-include libev/ev.h"],
				 [AC_MSG_ERROR([ev.h not found])])])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
