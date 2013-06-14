# If you want to build outside of the source tree, use the -f option:
#     make -f ${SOMEWHERE}/proot/src/GNUmakefile

# the VPATH variable must points to the actual makefile directory
MAKEDIR := $(dir $(MAKEFILE_LIST))
VPATH	:= $(MAKEDIR)
GIT      = git
RM       = rm
INSTALL  = install
CC       = gcc
LD       = $(CC)
CPPFLAGS = -I. -I$(VPATH)
CFLAGS   = -Wall -Wextra -O2
LDFLAGS  = -ltalloc

ifdef LIMITED_USE
# For limited use and MIT license
STATIC_BUILD=1
LICENSE_MIT=1
DAYS_LIMIT=30
STRIP_INSTALL=1
endif

ifdef LICENSE_MIT
I_CPPFLAGS  += -DLICENSE_MIT
endif

ifdef DAYS_LIMIT
STATIC_BUILD=1
TIME_NOW := $(shell date +%s)
TIME_LIMIT:= $(shell date -d"$(DAYS_LIMIT) days" +%s)
DATE_LIMIT:= $(shell date -d"$(DAYS_LIMIT) days" -u +"%Y-%m-%dUTC")
I_CPPFLAGS   += -DDAYS_LIMIT=$(DAYS_LIMIT) -DDATE_LIMIT=$(DATE_LIMIT) -DTIME_NOW=$(TIME_NOW) -DTIME_LIMIT=$(TIME_LIMIT)
endif

ifdef STRIP_INSTALL
INSTALL=install -s
endif

ifdef STATIC_BUILD
I_LDFLAGS  += -static
endif

ifdef ENABLE_ADDONS
# For care addon
ENABLE_CEC_LIB=1
endif

OBJECTS = cli.o			\
	notice.o		\
	execve/execve.o		\
	execve/interp.o		\
	execve/elf.o		\
	execve/ldso.o		\
	path/binding.o		\
	path/glue.o		\
	path/canon.o		\
	path/path.o		\
	path/proc.o		\
	syscall/seccomp.o	\
	syscall/syscall.o	\
	syscall/socket.o	\
	tracee/tracee.o		\
	tracee/array.o		\
	tracee/mem.o		\
	tracee/reg.o		\
	tracee/event.o		\
	extension/extension.o	\
	extension/kompat/kompat.o \
	extension/fake_id0/fake_id0.o


ifdef ENABLE_CEC_LIB
I_CPPFLAGS  += -I$(VPATH)/cec_lib
OBJECTS += cec_lib/cec_hash.o
endif


# The ENABLE_ADDONS must be a space separated list of addons
ifdef ENABLE_ADDONS
OBJECTS += addons/syscall_addons.o
I_CPPFLAGS += -DENABLE_ADDONS
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

CHECK_FEATURES = readlinkat process_vm seccomp_filter
CHECK_PROGRAMS = $(foreach feature,$(CHECK_FEATURES),.check_$(feature))
CHECK_OBJECTS  = $(foreach feature,$(CHECK_FEATURES),.check_$(feature).o)

.SILENT .IGNORE .INTERMEDIATE: $(CHECK_OBJECTS)

.check_%.o: .check_%.c
	$(COMPILE:echo=false) $(silently) || true

.check_%: .check_%.o
	$(LINK:echo=false) $(silently) || true

# TODO: generate these lines automatically from $(CHECK_FEATURES)
CHECK_READLINKAT = if [ -e .check_readlinkat ]; then echo "\#define HAVE_READLINKAT"; fi
CHECK_PROCESS_VM = if [ -e .check_process_vm ]; then echo "\#define HAVE_PROCESS_VM"; fi
CHECK_SECCOMP_FILTER = if [ -e .check_seccomp_filter ]; then echo "\#define HAVE_SECCOMP_FILTER"; fi

build.h: $(CHECK_PROGRAMS)
	$($(quiet)GEN)
	$(Q)echo "/* This file is auto-generated, edit at your own risk.  */" > $@
	$(Q)echo "#ifndef BUILD_H"      >> $@
	$(Q)echo "#define BUILD_H"      >> $@
	$(Q)sh -c '$(CHECK_VERSION)'     >> $@
	$(Q)sh -c '$(CHECK_READLINKAT)'  >> $@
	$(Q)sh -c '$(CHECK_ADDONS)'  >> $@
	$(Q)sh -c '$(CHECK_PROCESS_VM)'  >> $@
	$(Q)sh -c '$(CHECK_SECCOMP_FILTER)' >> $@
	$(Q)echo "#endif /* BUILD_H */" >> $@

######################################################################
# Build rules

SRC     = $(dir $(firstword $(MAKEFILE_LIST)))
COMPILE = $($(quiet)CC) $(CPPFLAGS) $(I_CPPFLAGS) $(CFLAGS) $(I_CFLAGS) -MD -c $(SRC)$(@:.o=.c) -o $@
LINK    = $($(quiet)LD) -o $@ $^ $(LDFLAGS) $(I_LDFLAGS)

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

DEPS = $(OBJECTS:.o=.d) $(CHECK_OBJECTS:.o=.d)
-include $(DEPS)

######################################################################
# PHONY targets

PREFIX = /usr/local
DESTDIR = $(PREFIX)/bin

.PHONY: clean distclean install uninstall
clean distclean:
	-$(RM) -f $(CHECK_PROGRAMS) $(CHECK_OBJECTS) $(OBJECTS) proot $(DEPS) build.h

install: proot
	$($(quiet)INSTALL) -D $< $(DESTDIR)/$<

uninstall:
	-$(RM) -f $(DESTDIR)/proot
