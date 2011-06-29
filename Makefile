# Makefile for tcpstat
#
#

# installation root directory
PREFIX=/usr/local

SYS=$(shell uname -s)

# Compiler 
CC=gcc
# install program 
INSTALL=install

INCLDIRS	= -Isrc/ -Isrc/ui -Isrc/scouts

# Default compilation flags
CFLAGS= -Wall -Wextra -Wshadow -O2 -g -std=gnu99 $(INCLDIRS)
LFLAGS= -lncurses -lpcap

ifeq ($(PROFILE),1)
		CFLAGS += -g -pg 
		LFLAGS += -pg 
endif
ifeq ($(32BIT),1)
  	CFLAGS += -m32
	LFLAGS += -m32
endif
ifeq ($(SYS),OpenBSD)
	CFLAGS += -DOPENBSD
	LFLAGS += -lkvm
endif
ifeq ($(SYS),Linux)
	CFLAGS += -DLINUX
endif
ifeq ($(SYS),Darwin)
	CFLAGS += -DOSX
endif


ifdef BUILDID
	CFLAGS += -DBUILDID=\"$(BUILDID)\"
endif 

## Doxygen definitions 
DOXYGEN=doxygen
DOXYFILE=Doxyfile 

## install options
INSTALL_MODE= 755
INSTALL_BINDIR= $(PREFIX)/bin

INSTALL_FLAGS=-s -m $(INSTALL_MODE)

## Program definitions 
OBJS= debug.o stat.o tcpstat.o parser.o connection.o  group.o filter.o 
UI_OBJS= printout_curses.o view.o banners.o main_view.o endpoint_view.o help_view.o
PKT_OBJS= packet_reader.o tcpip.o
ifeq ($(SYS),Linux)
	SCOUT_OBJS= ifscout.o pidscout.o tcpscout.o rtscout.o packetscout.o 
endif
ifeq ($(SYS),OpenBSD)
	SCOUT_OBJS= ifscout.o tcpscout_bsd.o packetscout.o
endif
ifeq ($(SYS),Darwin)
	SCOUT_OBJS= ifscout.o tcpscout_osx.o packetscout.o
endif

PROGNAME=tcpstat
COMMON_HDRS=src/debug.h src/defs.h src/connection.h src/filter.h

.PHONY : all clean prog test chashtest docs docclean allclean install

## targets 

all	: prog 

docs    :
	$(DOXYGEN) $(DOXYFILE)

prog	: $(OBJS) $(UI_OBJS) $(SCOUT_OBJS) $(PKT_OBJS)
	$(CC) -o $(PROGNAME) $(OBJS) $(UI_OBJS) $(SCOUT_OBJS) $(PKT_OBJS) $(LFLAGS)

# Rule for objects on src
%.o	: src/%.c $(COMMON_HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o	: src/ui/%.c $(COMMON_HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o	: src/scouts/%.c $(COMMON_HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o	: src/packet/%.c $(COMMON_HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

clean	:
	rm -f $(OBJS) $(UI_OBJS) $(SCOUT_OBJS) $(PROGNAME) $(PKT_OBJS) core.* 

docclean :
	rm -rf doc/html/* 

allclean : clean docclean

install	:
	$(INSTALL) $(INSTALL_FLAGS) -t $(INSTALL_BINDIR) $(PROGNAME)



