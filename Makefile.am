SUBDIRS = include .

if DEBUG
CONFIG_FILE=isolate.cf
else !DEBUG
CONFIG_FILE=$(sysconfdir)/isolate.cf
endif

libisolateconfdir=$(sysconfdir)
libisolateconf_DATA = isolate.cf

AM_CPPFLAGS = -I$(top_srcdir)/src/  -include $(top_srcdir)/include/config.h -DCONFIG_FILE=\"$(CONFIG_FILE)\"


AM_LDFLAGS = -shared -O3 -lcap


lib_LTLIBRARIES = libisolate.la
# Put here all the source files
# that need to be compiled with
# the dynamic library.
source_files = \
	src/cg.c  \
	src/config.c \
	src/isolate.c  \
	src/rules.c \
	src/isolate.h \
	src/util.c

header_files = \
	src/isolate.h

libisolate_la_LDFLAGS = -lcap
libisolate_la_SOURCES = $(source_files) $(header_files)
