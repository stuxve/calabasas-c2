# Makefile for cross-compiling BOF modules via MinGW-w64.
#
# Usage:
#   make              — build all BOFs (x64)
#   make ARCH=x86     — build all BOFs (x86)
#   make validate     — verify COFF headers are valid
#   make clean        — remove compiled .o files
#
# Each BOF is compiled as a relocatable object file (-c flag).
# The agent's COFF loader handles linking at runtime.

CC_x64  = x86_64-w64-mingw32-gcc
CC_x86  = i686-w64-mingw32-gcc

ARCH ?= x64
CC = $(CC_$(ARCH))

# Compiler flags for BOFs:
#   -c              = compile only (no linking)
#   -Os             = optimize for size
#   -fno-asynchronous-unwind-tables  = no .pdata/.xdata (smaller BOF)
#   -fno-ident      = no compiler ident string
#   -fpack-struct=8 = pack structs to 8-byte alignment (x64 ABI)
CFLAGS = -c -Wall -Wextra -Os \
         -fno-asynchronous-unwind-tables -fno-ident -fpack-struct=8

# Include path for beacon_compat.h
INCLUDES = -I../shared/include

# ─── Module definitions ───
# Format: MODULE_NAME = category/name
ENUM_MODULES = enumdomainusers enumdomaingroups enumspns ldapsearch
CRED_MODULES = kerberoast asreproast dcsync dumplsass extracttickets ptt overpassthehash
LATERAL_MODULES = wmiexec smbexec psexec scshell
EVASION_MODULES = patchamsi patchetw unhookntdll blockdlls ppidspoof timestomp

ALL_MODULES = $(ENUM_MODULES) $(CRED_MODULES) $(LATERAL_MODULES) $(EVASION_MODULES)

.PHONY: all clean validate $(ALL_MODULES)

all: $(ALL_MODULES)
	@echo "[*] All BOFs built ($(ARCH))"

# ─── Enumeration modules ───

enumdomainusers:
	@mkdir -p enumeration/enumdomainusers/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o enumeration/enumdomainusers/bin/enumdomainusers.$(ARCH).o \
		enumeration/enumdomainusers/src/enumdomainusers.c
	@echo "  [+] enumdomainusers.$(ARCH).o"

enumdomaingroups:
	@mkdir -p enumeration/enumdomaingroups/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o enumeration/enumdomaingroups/bin/enumdomaingroups.$(ARCH).o \
		enumeration/enumdomaingroups/src/enumdomaingroups.c
	@echo "  [+] enumdomaingroups.$(ARCH).o"

enumspns:
	@mkdir -p enumeration/enumspns/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o enumeration/enumspns/bin/enumspns.$(ARCH).o \
		enumeration/enumspns/src/enumspns.c
	@echo "  [+] enumspns.$(ARCH).o"

ldapsearch:
	@mkdir -p enumeration/ldapsearch/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o enumeration/ldapsearch/bin/ldapsearch.$(ARCH).o \
		enumeration/ldapsearch/src/ldapsearch.c
	@echo "  [+] ldapsearch.$(ARCH).o"

# ─── Credential modules ───

kerberoast:
	@mkdir -p credentials/kerberoast/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o credentials/kerberoast/bin/kerberoast.$(ARCH).o \
		credentials/kerberoast/src/kerberoast.c
	@echo "  [+] kerberoast.$(ARCH).o"

asreproast:
	@mkdir -p credentials/asreproast/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o credentials/asreproast/bin/asreproast.$(ARCH).o \
		credentials/asreproast/src/asreproast.c
	@echo "  [+] asreproast.$(ARCH).o"

dcsync:
	@mkdir -p credentials/dcsync/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o credentials/dcsync/bin/dcsync.$(ARCH).o \
		credentials/dcsync/src/dcsync.c
	@echo "  [+] dcsync.$(ARCH).o"

dumplsass:
	@mkdir -p credentials/dumplsass/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o credentials/dumplsass/bin/dumplsass.$(ARCH).o \
		credentials/dumplsass/src/dumplsass.c
	@echo "  [+] dumplsass.$(ARCH).o"

extracttickets:
	@mkdir -p credentials/extracttickets/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o credentials/extracttickets/bin/extracttickets.$(ARCH).o \
		credentials/extracttickets/src/extracttickets.c
	@echo "  [+] extracttickets.$(ARCH).o"

ptt:
	@mkdir -p credentials/ptt/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o credentials/ptt/bin/ptt.$(ARCH).o \
		credentials/ptt/src/ptt.c
	@echo "  [+] ptt.$(ARCH).o"

overpassthehash:
	@mkdir -p credentials/overpassthehash/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o credentials/overpassthehash/bin/overpassthehash.$(ARCH).o \
		credentials/overpassthehash/src/overpassthehash.c
	@echo "  [+] overpassthehash.$(ARCH).o"

# ─── Lateral movement modules ───

wmiexec:
	@mkdir -p lateral_movement/wmiexec/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o lateral_movement/wmiexec/bin/wmiexec.$(ARCH).o \
		lateral_movement/wmiexec/src/wmiexec.c
	@echo "  [+] wmiexec.$(ARCH).o"

smbexec:
	@mkdir -p lateral_movement/smbexec/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o lateral_movement/smbexec/bin/smbexec.$(ARCH).o \
		lateral_movement/smbexec/src/smbexec.c
	@echo "  [+] smbexec.$(ARCH).o"

psexec:
	@mkdir -p lateral_movement/psexec/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o lateral_movement/psexec/bin/psexec.$(ARCH).o \
		lateral_movement/psexec/src/psexec.c
	@echo "  [+] psexec.$(ARCH).o"

scshell:
	@mkdir -p lateral_movement/scshell/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o lateral_movement/scshell/bin/scshell.$(ARCH).o \
		lateral_movement/scshell/src/scshell.c
	@echo "  [+] scshell.$(ARCH).o"

# ─── Evasion modules ───

patchamsi:
	@mkdir -p evasion/patchamsi/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o evasion/patchamsi/bin/patchamsi.$(ARCH).o \
		evasion/patchamsi/src/patchamsi.c
	@echo "  [+] patchamsi.$(ARCH).o"

patchetw:
	@mkdir -p evasion/patchetw/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o evasion/patchetw/bin/patchetw.$(ARCH).o \
		evasion/patchetw/src/patchetw.c
	@echo "  [+] patchetw.$(ARCH).o"

unhookntdll:
	@mkdir -p evasion/unhookntdll/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o evasion/unhookntdll/bin/unhookntdll.$(ARCH).o \
		evasion/unhookntdll/src/unhookntdll.c
	@echo "  [+] unhookntdll.$(ARCH).o"

blockdlls:
	@mkdir -p evasion/blockdlls/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o evasion/blockdlls/bin/blockdlls.$(ARCH).o \
		evasion/blockdlls/src/blockdlls.c
	@echo "  [+] blockdlls.$(ARCH).o"

ppidspoof:
	@mkdir -p evasion/ppidspoof/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o evasion/ppidspoof/bin/ppidspoof.$(ARCH).o \
		evasion/ppidspoof/src/ppidspoof.c
	@echo "  [+] ppidspoof.$(ARCH).o"

timestomp:
	@mkdir -p evasion/timestomp/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o evasion/timestomp/bin/timestomp.$(ARCH).o \
		evasion/timestomp/src/timestomp.c
	@echo "  [+] timestomp.$(ARCH).o"

# ─── Validation ───

validate:
	@echo "[*] Validating COFF headers..."
	@fail=0; \
	for f in $$(find . -name "*.$(ARCH).o" -path "*/bin/*"); do \
		magic=$$(xxd -l 2 -p "$$f" 2>/dev/null); \
		if [ "$(ARCH)" = "x64" ] && [ "$$magic" != "6486" ]; then \
			echo "  INVALID: $$f (magic=$$magic, expected=6486)"; \
			fail=1; \
		elif [ "$(ARCH)" = "x86" ] && [ "$$magic" != "4c01" ]; then \
			echo "  INVALID: $$f (magic=$$magic, expected=4c01)"; \
			fail=1; \
		else \
			echo "  OK: $$f"; \
		fi; \
	done; \
	if [ $$fail -eq 1 ]; then echo "[!] Validation FAILED"; exit 1; fi; \
	echo "[*] All BOFs valid"

# ─── Cleanup ───

clean:
	find . -name "*.o" -path "*/bin/*" -delete
	@echo "[*] Cleaned BOF binaries"
