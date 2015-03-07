#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([igmping], [1.0], [pkrebs@gmail.com])
AC_PREFIX_DEFAULT([/usr])
AM_INIT_AUTOMAKE()
AC_CONFIG_SRCDIR([src/igmping.c])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime memset socket strtoul])

AC_OUTPUT(Makefile src/Makefile man/Makefile)
