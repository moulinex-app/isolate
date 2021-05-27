AC_INIT([isolate-lib], [v1.8.2], [simon.scatton@outlook.fr])

AC_CONFIG_SRCDIR([src/])

AM_INIT_AUTOMAKE([
  -Wall
  -Werror
  foreign
  subdir-objects
]
)

AM_SILENT_RULES([yes])


AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_AR


AC_CONFIG_MACRO_DIRS([m4])

LT_PREREQ([2.2])
LT_INIT([dlopen shared])

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [enable debug build]), [], [])

AS_IF([test "$enable_debug" = "yes"], [
        AC_DEFINE([DEBUG], [1], [debug build])
])


AH_TEMPLATE([DEBUG],
            [Define to 1 if debug is enabled, 0 otherwise])

AM_CONDITIONAL([DEBUG], [test "$enable_debug" = "yes"])


AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_FILES([Makefile include/Makefile isolate.pc])
# Output the files
AC_OUTPUT
