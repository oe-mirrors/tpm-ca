#!/usr/bin/make -f
#
# Copyright (C) 2014 Dream Property GmbH, Germany
#                    http://www.dream-multimedia-tv.de/
#

prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin

override CFLAGS := $(CFLAGS) -Wall -Wextra -std=c99
override CPPFLAGS := $(CPPFLAGS) -DNDEBUG -MD
override LDLIBS := -lcrypto

TARGETS := tpm-ca

default: $(TARGETS)

tpm-ca: tpm-ca.o

clean:
	$(RM) $(TARGETS) *.[do]

install: $(TARGETS)
	install -d $(DESTDIR)$(bindir)
	install -m 755 $(TARGETS) $(DESTDIR)$(bindir)

-include $(wildcard *.d)
