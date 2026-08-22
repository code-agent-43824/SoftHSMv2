MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

SUBDIRS = common keyconv util export dump

if BUILD_MIGRATE
SUBDIRS += migrate
endif

EXTRA_DIST =	$(srcdir)/CMakeLists.txt \
		$(srcdir)/win32/*.cpp
