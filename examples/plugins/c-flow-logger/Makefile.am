plugindir = ${libdir}/suricata/plugins

if BUILD_SHARED_LIBRARY
plugin_LTLIBRARIES = flowlogger.la
flowlogger_la_LDFLAGS = -module -shared
flowlogger_la_SOURCES = flowlogger.c

flowlogger_la_CPPFLAGS = -I$(abs_top_srcdir)/rust/gen -I$(abs_top_srcdir)/rust/dist

else

all-local:
	@echo
	@echo "Shared library support must be enabled to build plugins."
	@echo

endif
