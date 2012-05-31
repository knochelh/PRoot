# If you want to build outside of the source tree, use the -f option:
#     make -f ${SOMEWHERE}/proot/src/GNUmakefile

# the VPATH variable must points to the actual makefile directory
MAKEDIR := $(dir $(lastword $(MAKEFILE_LIST)))
VPATH	:= $(MAKEDIR)
GIT      = git
RM       = rm
INSTALL  = install
CC       = gcc
LD       = $(CC)
CPPFLAGS = -I. -I$(VPATH)
CFLAGS   = -Wall -O0 -g
LDFLAGS  = 

ifdef LIMITED_USE
# For limited use and MIT license
STATIC_BUILD=1
LICENSE_MIT=1
DAYS_LIMIT=30
STRIP_INSTALL=1
endif

ifdef LICENSE_MIT
CFLAGS  += -DLICENSE_MIT
endif

ifdef DAYS_LIMIT
STATIC_BUILD=1
TIME_NOW := $(shell date +%s)
TIME_LIMIT:= $(shell date -d"$(DAYS_LIMIT) days" +%s)
DATE_LIMIT:= $(shell date -d"@$(TIME_LIMIT)" -u +"%Y-%m-%dUTC")
CFLAGS   += -DDAYS_LIMIT=$(DAYS_LIMIT) -DDATE_LIMIT=$(DATE_LIMIT) -DTIME_NOW=$(TIME_NOW) -DTIME_LIMIT=$(TIME_LIMIT)
endif

ifdef STRIP_INSTALL
INSTALL=install -s
endif

ifdef STATIC_BUILD
LDFLAGS  += -static
endif

ifdef ENABLE_ADDONS
# For care addon
ENABLE_GLIB=1
endif

ifdef ENABLE_GLIB
GLIB_CFLAGS := $(shell pkg-config glib-2.0 --cflags)
ifdef STATIC_BUILD
GLIB_LIBS := $(shell pkg-config glib-2.0 --libs --static)
else
GLIB_LIBS := $(shell pkg-config glib-2.0 --libs)
endif
CFLAGS  += $(GLIB_CFLAGS)
LIBS    += $(GLIB_LIBS)
endif

OBJECTS = cli.o			\
	config.o		\
	notice.o		\
	trace.o			\
	execve/args.o		\
	execve/execve.o		\
	execve/interp.o		\
	execve/elf.o		\
	execve/ldso.o		\
	path/binding.o		\
	path/canon.o		\
	path/path.o		\
	syscall/syscall.o	\
	tracee/info.o		\
	tracee/mem.o		\
	tracee/ureg.o

# The ENABLE_ADDONS must be a space separated list of addons
ifneq ($(ENABLE_ADDONS),)
OBJECTS += addons/syscall_addons.o
CPPFLAGS += -DENABLE_ADDONS
OBJECTS += $(subst $(MAKEDIR)/,,$(subst .c,.o,$(wildcard $(addsuffix /*.c, $(addprefix $(MAKEDIR)/addons/, $(ENABLE_ADDONS))))))
endif


.DEFAULT_GOAL = proot
all: proot

######################################################################
# Beautified output

quiet_GEN = @echo "  GEN	$@"; $(GEN)
quiet_CC  = @echo "  CC	$@"; $(CC)
quiet_LD  = @echo "  LD	$@"; $(LD)
quiet_INSTALL = @echo "  INSTALL	$?"; $(INSTALL)

V = 0
ifeq ($(V), 0)
    quiet = quiet_
    Q     = @
    silently = >/dev/null 2>&1
else
    quiet = 
    Q     = 
    silently = 
endif

######################################################################
# Auto-configuration

CHECK_VERSION = VERSION=$$($(GIT) describe --tags --dirty --abbrev=8 --always 2>/dev/null); \
		if [ ! -z "$${VERSION}" ]; \
		then /bin/echo -e "\#undef VERSION\n\#define VERSION \"$${VERSION}\""; \
		fi;

CHECK_ADDONS = 	if [ ! -z "$(ENABLE_ADDONS)" ]; \
		then /bin/echo -e "\#define ADDONS \"$(ENABLE_ADDONS)\""; \
		fi;

.SILENT .IGNORE .INTERMEDIATE: .check_readlinkat .check_readlinkat.o

.check_readlinkat.o: .check_readlinkat.c
	$(COMPILE:echo=false) $(silently) || true

.check_readlinkat: .check_readlinkat.o
	$(LINK:echo=false) $(silently) || true

CHECK_READLINKAT = if [ -e .check_readlinkat ]; then echo "\#define HAVE_READLINKAT"; fi

build.h: .check_readlinkat
	$($(quiet)GEN)
	$(Q)echo "/* This file is auto-generated, edit at your own risk.  */" > $@
	$(Q)echo "#ifndef BUILD_H"      >> $@
	$(Q)echo "#define BUILD_H"      >> $@
	$(Q)sh -c '$(CHECK_VERSION)'     >> $@
	$(Q)sh -c '$(CHECK_READLINKAT)'  >> $@
	$(Q)sh -c '$(CHECK_ADDONS)'  >> $@
	$(Q)echo "#endif /* BUILD_H */" >> $@

######################################################################
# Build rules

SRC     = $(dir $(firstword $(MAKEFILE_LIST)))
COMPILE = $($(quiet)CC) $(CPPFLAGS) $(CFLAGS) -MD -c $(SRC)$*.c -o $@
LINK    = $($(quiet)LD) $(LDFLAGS) -o $@ $^ $(LIBS)

proot: $(OBJECTS)
	$(LINK)

# Special case to compute which files depend on the auto-generated
# file "build.h".
USE_BUILD_H := $(patsubst $(SRC)%,%,$(patsubst %.c,%.o,$(shell egrep -l 'include[[:space:]]+"build.h"' $(SRC)*.c $(SRC)*/*.c)))
$(USE_BUILD_H): build.h

%.o: %.c
	@mkdir -p $(dir $@)
	$(COMPILE)

######################################################################
# Dependencies

.DELETE_ON_ERROR:
$(OBJECTS) build.h: $(firstword $(MAKEFILE_LIST))

DEPS = $(OBJECTS:.o=.d) .check_readlinkat.d
-include $(DEPS)

######################################################################
# PHONY targets

PREFIX = /usr/local
DESTDIR = $(PREFIX)/bin

.PHONY: clean distclean install uninstall
clean distclean:
	-$(RM) -f $(OBJECTS) proot $(DEPS) build.h

install: proot
	$($(quiet)INSTALL) -D $< $(DESTDIR)/$<

uninstall:
	-$(RM) -f $(DESTDIR)/proot
