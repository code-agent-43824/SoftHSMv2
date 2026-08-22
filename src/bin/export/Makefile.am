MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = -DSOFTHSM2_ENABLE_DEBUG_EXPORT=1 -DCRYPTOKI_STATIC=1 \
	-I$(srcdir)/../common \
	-I$(srcdir)/../../lib \
	-I$(srcdir)/../../lib/common \
	-I$(srcdir)/../../lib/crypto \
	-I$(srcdir)/../../lib/data_mgr \
	-I$(srcdir)/../../lib/handle_mgr \
	-I$(srcdir)/../../lib/object_store \
	-I$(srcdir)/../../lib/pkcs11 \
	-I$(srcdir)/../../lib/session_mgr \
	-I$(srcdir)/../../lib/slot_mgr \
	@CRYPTO_INCLUDES@ @SQLITE3_INCLUDES@

bin_PROGRAMS = softhsm2-export

AUTOMAKE_OPTIONS = subdir-objects

softhsm2_export_SOURCES = softhsm2-export.cpp \
	../common/findslot.cpp \
	../common/getpw.cpp \
	../../lib/access.cpp \
	../../lib/main.cpp \
	../../lib/P11Attributes.cpp \
	../../lib/P11Objects.cpp \
	../../lib/SoftHSM.cpp

softhsm2_export_LDADD = ../../lib/libsofthsm_convarch.la \
	@CRYPTO_LIBS@ @SQLITE3_LIBS@

EXTRA_DIST = $(srcdir)/CMakeLists.txt $(srcdir)/*.cpp
