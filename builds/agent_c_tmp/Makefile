# Makefile for cross-compiling the C agent from Linux (Kali) using MinGW-w64.
#
# Usage:
#   make              — build x64 agent
#   make ARCH=x86     — build x86 agent
#   make clean        — remove build artifacts

CC_x64  = x86_64-w64-mingw32-gcc
CC_x86  = i686-w64-mingw32-gcc
STRIP_x64 = x86_64-w64-mingw32-strip
STRIP_x86 = i686-w64-mingw32-strip

ARCH ?= x64
CC = $(CC_$(ARCH))
STRIP = $(STRIP_$(ARCH))

SRCDIR  = src
INCDIR  = include
OUTDIR  = build

SRCS = $(SRCDIR)/main.c \
       $(SRCDIR)/protocol.c \
       $(SRCDIR)/crypto.c \
       $(SRCDIR)/channel.c \
       $(SRCDIR)/modules.c \
       $(SRCDIR)/utils.c

CFLAGS  = -I$(INCDIR) -Wall -Wextra -Os -s \
          -fno-asynchronous-unwind-tables -fno-ident \
          -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0603

LDFLAGS = -lbcrypt -lwinhttp -ladvapi32 -lkernel32 -luser32 -lntdll \
          -static-libgcc -Wl,--subsystem,console

TARGET  = $(OUTDIR)/agent.exe

.PHONY: all clean

all: $(OUTDIR) $(TARGET)
	@echo "[*] Built $(TARGET) ($(ARCH))"

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	$(STRIP) $@
	@ls -la $@

# GUI subsystem (no console window)
gui: $(OUTDIR) $(SRCS)
	$(CC) $(CFLAGS) -o $(OUTDIR)/agent_gui.exe $(SRCS) $(LDFLAGS) -Wl,--subsystem,windows -DAGENT_GUI
	$(STRIP) $(OUTDIR)/agent_gui.exe

clean:
	rm -rf $(OUTDIR)
