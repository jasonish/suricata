pkglib_LTLIBRARIES = ja4t-stub.la

ja4t_stub_la_LDFLAGS = -module -avoid-version -shared

# Only required to find these headers when building plugins from the
# source directory.
ja4t_stub_la_CFLAGS = -I../../rust/gen -I../../rust/dist

ja4t_stub_la_SOURCES = ja4t-stub.c

install-exec-hook:
	cd $(DESTDIR)$(pkglibdir) && $(RM) $(pkglib_LTLIBRARIES)
