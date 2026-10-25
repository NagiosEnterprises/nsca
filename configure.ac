dnl Process this -*-m4-*- file with autoconf to produce a configure script.

dnl Disable caching
define([AC_CACHE_LOAD],)
define([AC_CACHE_SAVE],)

AC_INIT([nsca],[2.10.3],[nagios-users@lists.sourceforge.net],[nsca],[http://www.nagios.org])
AC_CONFIG_SRCDIR([src/nsca.c])
AC_CONFIG_HEADER(include/config.h)
AC_CONFIG_FILES([Makefile
	subst
	src/Makefile
	package/solaris/Makefile
	init-script
	nsca.service
	sample-config/nsca.cfg
	sample-config/send_nsca.cfg
	sample-config/nsca.xinetd])
AC_PREFIX_DEFAULT(/usr/local/nagios)

PKG_NAME=nsca
PKG_VERSION="2.10.3"
PKG_HOME_URL="http://www.nagios.org/"
PKG_REL_DATE="2024-08-01"
AC_SUBST(PKG_NAME)
AC_SUBST(PKG_VERSION)
AC_SUBST(PKG_HOME_URL)
AC_SUBST(PKG_REL_DATE)

dnl Figure out how to invoke "install" and what install options to use.
AC_PROG_INSTALL
AC_SUBST(INSTALL)

dnl What OS are we running?
AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(db.h ctype.h errno.h fcntl.h grp.h inttypes.h netdb.h pwd.h regex.h signal.h stdint.h strings.h string.h syslog.h tcpd.h unistd.h arpa/inet.h netinet/in.h sys/config.h sys/int_types.h sys/poll.h sys/types.h sys/time.h sys/resource.h sys/socket.h sys/stat.h sys/wait.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_VOLATILE
AC_STRUCT_TM
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SIGNAL
AC_TYPE_GETGROUPS

dnl Check lengths for later tests of u_int32_t and int32_t
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(long)

dnl Define u_int32_t if we don't have it already (Solaris, etc.)
AC_CHECK_TYPE(uint32_t,unsigned int)
AC_CHECK_TYPE(u_int32_t,unsigned int)
if test "$ac_cv_type_u_int32_t" = no ; then
	if test "$ac_cv_type_u_int32_t" = yes ; then
		AC_DEFINE(U_INT32_T_IS_UINT32_T,[1],[u_int32_t is uint32_t])
	else
		if test "$ac_cv_sizeof_int" = 4 ; then
			AC_DEFINE(U_INT32_T_IS_UINT,[1],[u_int32_t is uint])
		else
			if test "$ac_cv_sizeof_long" = 4 ; then
				AC_DEFINE(U_INT32_T_IS_ULONG,[1],[u_int32_t is ulong])
			else
				if test "$ac_cv_sizeof_short" = 4 ; then
					AC_DEFINE(U_INT32_T_IS_USHORT,[1],[u_int32_t is ushort])
				fi
			fi
		fi
	fi
fi

dnl Define int32_t if we don't have it already
AC_CHECK_TYPE(int32_t,int)
if test "$ac_cv_type_int32_t" = no ; then
	if test "$ac_cv_sizeof_int" = 4 ; then
		AC_DEFINE(INT32_T_IS_UINT,[1],[int32_t is uint])
	else
		if test "$ac_cv_sizeof_long" = 4 ; then
			AC_DEFINE(INT32_T_IS_ULONG,[1],[int32_t is ulong])
		else
			if test "$ac_cv_sizeof_short" = 4 ; then
				AC_DEFINE(INT32_T_IS_USHORT,[1],[int32_t is ushort])
			fi
		fi
	fi
fi

dnl Checks for library functions.
AC_CHECK_LIB(nsl,main,SOCKETLIBS="$SOCKETLIBS -lnsl")
AC_CHECK_LIB(socket,socket,SOCKETLIBS="$SOCKETLIBS -lsocket")
AC_SUBST(SOCKETLIBS)
AC_CHECK_LIB(wrap,main,[
	LIBWRAPLIBS="$LIBWRAPLIBS -lwrap"
	AC_DEFINE(HAVE_LIBWRAP,[1],[Have the TCP wrappers library])
	])
AC_SUBST(LIBWRAPLIBS)
AC_CHECK_FUNCS(strdup strstr strtoul sigaction)

dnl we require modern address resolution functions.
AC_CHECK_FUNCS([getnameinfo getaddrinfo], ,
	[AC_MSG_ERROR([Missing address resolution functions])])

dnl Define sig_atomic_t to int if it's not available.
AC_CHECK_TYPE([sig_atomic_t],[],[
	AC_DEFINE([sig_atomic_t],[int],
		[Define to 'int' if <signal.h> does not define.])
	],[
	#if HAVE_SIGNAL_H
	#include <signal.h>
	#endif
	])

dnl socklen_t check - from curl
AC_CHECK_TYPE([socklen_t], ,[
       AC_MSG_CHECKING([for socklen_t equivalent])
       AC_CACHE_VAL([curl_cv_socklen_t_equiv],
       [
          # Systems have either "struct sockaddr *" or
          # "void *" as the second argument to getpeername
          curl_cv_socklen_t_equiv=
          for arg2 in "struct sockaddr" void; do
             for t in int size_t unsigned long "unsigned long"; do
                AC_TRY_COMPILE([
                   #ifdef HAVE_SYS_TYPES_H
                   #include <sys/types.h>
                   #endif 
                   #ifdef HAVE_SYS_SOCKET_H
                   #include <sys/socket.h>
                   #endif
                   
                   int getpeername (int, $arg2 *, $t *);
                ],[
                   $t len;
                   getpeername(0,0,&len);
                ],[
                   curl_cv_socklen_t_equiv="$t"
                   break
                ])
             done
          done
 
          if test "x$curl_cv_socklen_t_equiv" = x; then
             AC_MSG_ERROR([Cannot find a type to use in place of socklen_t])
          fi
       ])
       AC_MSG_RESULT($curl_cv_socklen_t_equiv)
       AC_DEFINE_UNQUOTED(socklen_t, $curl_cv_socklen_t_equiv,
                         [type to use in place of socklen_t if not defined])],
       [#include <sys/types.h>
#include <sys/socket.h>])

AC_MSG_CHECKING(for type of socket size)
AC_TRY_COMPILE([#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
],
[int a = send(1, (const void *)0, (size_t *) 0, (int *) 0);],
[AC_DEFINE(SOCKET_SIZE_TYPE, size_t, [Socket Size Type]) AC_MSG_RESULT(size_t)],
[AC_DEFINE(SOCKET_SIZE_TYPE, int, [Socket Size Type]) AC_MSG_RESULT(int)])

dnl Optional libgcrypt library and include paths
AC_ARG_WITH(gcrypt-lib,--with-gcrypt-lib=DIR sets location of the libgcrypt library,[
	LDFLAGS="${LDFLAGS} -L${withval}"
	LD_RUN_PATH="${withval}${LD_RUN_PATH:+:}${LD_RUN_PATH}"
	])
AC_ARG_WITH(gcrypt-inc,--with-gcrypt-inc=DIR sets location of the libgcrypt include files,[
	CFLAGS="${CFLAGS} -I${withval}"
	])

dnl Check for libgcrypt (1.8.0 or newer, for 8-bit CFB mode)
GCRYPTLIBFOUND=nope
AC_CHECK_HEADER(gcrypt.h,[
	AC_CHECK_LIB(gcrypt,gcry_check_version,[
		AC_CHECK_DECL(GCRY_CIPHER_MODE_CFB8,GCRYPTLIBFOUND=yep,,[#include <gcrypt.h>])
		])
	])

if test x$GCRYPTLIBFOUND = xyep; then
	AC_DEFINE(HAVE_LIBGCRYPT,1,[Have the libgcrypt library])
	LIBS="${LIBS} -lgcrypt"
fi

dnl Did we find libgcrypt?
if test x$GCRYPTLIBFOUND = xnope; then
	echo ""
	echo ""
	echo "**************************************************************"
	echo "LIBGCRYPT (1.8.0 OR NEWER) COULD NOT BE LOCATED..."
	echo ""
	echo "The libgcrypt library could not be located on your system."
	echo "This means that you will NOT be able to use any crypto"
	echo "algorithms in the NSCA client or daemon."
	echo ""
	echo "Read the SECURITY text file for more information on why"
	echo "encryption is important to ensuring that the NSCA daemon is"
	echo "not abused by malicious users."
	echo ""
	echo "Most systems ship libgcrypt; install the development package"
	echo "(e.g. libgcrypt20-dev on Debian/Ubuntu, libgcrypt-devel on"
	echo "RHEL/Fedora/SUSE), or download it from:"
	echo ""
	echo "        https://gnupg.org/software/libgcrypt/"
	echo ""
	echo "If it is installed in a non-standard location, use the"
	echo "--with-gcrypt-lib and --with-gcrypt-inc options, then run"
	echo "'make devclean' and rerun the configure script."
	echo ""
	echo "**************************************************************"
	echo ""
fi


AC_ARG_WITH(log_facility,--with-log-facility=<facility> sets NSCA syslog facility,log_facility=$withval,log_facility=daemon)
AC_SUBST(log_facility)
AC_DEFINE_UNQUOTED(NSCA_LOG_FACILITY,["$log_facility"],[NSCA syslog facility])

AC_ARG_WITH(nsca_user,--with-nsca-user=<user> sets user name to run NSCA,nsca_user=$withval,nsca_user=nagios)
AC_ARG_WITH(nsca_grp,--with-nsca-grp=<grp> sets group name to run NSCA,nsca_grp=$withval,nsca_grp=nagios)
AC_ARG_WITH(nsca_port,--with-nsca-port=<port> sets port number for NSCA to listen on,nsca_port=$withval,nsca_port=5667)
AC_SUBST(nsca_user)
AC_SUBST(nsca_grp)
AC_SUBST(nsca_port)
AC_DEFINE_UNQUOTED(DEFAULT_SERVER_PORT,$nsca_port,[Default port for NSCA daemon])

# Determine target OS, version and architecture for package build macros
if test "x$target_ver" = "x" ; then
	TARGET_VER=`uname -r`
else
	TARGET_VER=$target_ver
fi
AC_SUBST(TARGET_VER)
if test "x$target_os" = "x" ; then
	TARGET_OS=`uname -s`
else
	TARGET_OS=$target_os
fi
AC_SUBST(TARGET_OS)
if test "x$target_cpu" = "x" ; then
	TARGET_ARCH=`uname -p`
else
	TARGET_ARCH=$target_cpu
fi
AC_SUBST(TARGET_ARCH)
TARGET_PLATFORM=""
if test "x$TARGET_OS" = "xSunOS" ; then
	if test "x$TARGET_VER" = "x5.10" ; then
		TARGET_PLATFORM="sol10"
	fi
fi
AC_SUBST(TARGET_PLATFORM)

AC_PATH_PROG(PERL,perl)
AC_OUTPUT()

perl subst init-script
perl subst nsca.service
perl subst sample-config/nsca.xinetd
perl subst sample-config/nsca.cfg
perl subst sample-config/send_nsca.cfg


dnl Review options
echo ""
echo ""
AC_MSG_RESULT([*** Configuration summary for $PKG_NAME $PKG_VERSION $PKG_REL_DATE ***:])

echo ""
echo " General Options:"
echo " -------------------------"

AC_MSG_RESULT([ NSCA port:  $nsca_port])
AC_MSG_RESULT([ NSCA user:  $nsca_user])
AC_MSG_RESULT([ NSCA group: $nsca_grp])


echo ""
echo ""
echo "Review the options above for accuracy.  If they look okay,"
echo "type 'make all' to compile the NSCA daemon and client."
echo ""

