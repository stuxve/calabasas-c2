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
         -fno-asynchronous-unwind-tables -fno-ident -fpack-struct=8 \
         -mno-stack-arg-probe

# Include path for beacon_compat.h
INCLUDES = -I../shared/include

# ─── Module definitions ───
# Format: MODULE_NAME = category/name
ENUM_MODULES = enumdomainusers enumdomaingroups enumspns ldapsearch
CRED_MODULES = kerberoast asreproast dcsync dumplsass extracttickets ptt overpassthehash hashdump underlaycopy
LATERAL_MODULES = wmiexec smbexec psexec scshell
EVASION_MODULES = patchamsi patchetw unhookntdll blockdlls ppidspoof timestomp
TICKET_MODULES  = requesttgt requesttgs klist tickets_ptt purgetickets tgtdeleg \
                  describeticket hash renewticket changepw s4u cross_s4u \
                  kerberoasting asreproasting dump triage

UTILITY_MODULES = execute_assembly

ALL_MODULES = $(ENUM_MODULES) $(CRED_MODULES) $(LATERAL_MODULES) $(EVASION_MODULES) $(TICKET_MODULES) $(UTILITY_MODULES)

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

LD_x64 = x86_64-w64-mingw32-ld
LD_x86 = i686-w64-mingw32-ld
LD = $(LD_$(ARCH))

DCSYNC_DIR     = credentials/dcsync
DCSYNC_SRC     = $(DCSYNC_DIR)/src
DCSYNC_INC     = $(DCSYNC_DIR)/include
DCSYNC_BIN     = $(DCSYNC_DIR)/bin
DCSYNC_INCLUDES = -I$(DCSYNC_INC) $(INCLUDES)

DCSYNC_SRCS = $(DCSYNC_SRC)/dcsync.c \
              $(DCSYNC_SRC)/ldap_helpers.c \
              $(DCSYNC_SRC)/ldap_syncall.c \
              $(DCSYNC_SRC)/rpc_adapter.c \
              $(DCSYNC_SRC)/ms_drsr_stubs.c

DCSYNC_OBJDIR = $(DCSYNC_BIN)/obj
DCSYNC_OBJS = $(patsubst $(DCSYNC_SRC)/%.c,$(DCSYNC_OBJDIR)/%.$(ARCH).o,$(DCSYNC_SRCS))

dcsync: $(DCSYNC_OBJS)
	$(LD) -r -o $(DCSYNC_BIN)/dcsync.$(ARCH).o $(DCSYNC_OBJS)
	@echo "  [+] dcsync.$(ARCH).o (linked from $(words $(DCSYNC_OBJS)) objects)"

$(DCSYNC_OBJDIR)/%.$(ARCH).o: $(DCSYNC_SRC)/%.c
	@mkdir -p $(DCSYNC_OBJDIR)
	$(CC) $(CFLAGS) $(DCSYNC_INCLUDES) -o $@ $<

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

hashdump:
	@mkdir -p credentials/hashdump/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o credentials/hashdump/bin/hashdump.$(ARCH).o \
		credentials/hashdump/src/hashdump.c
	@echo "  [+] hashdump.$(ARCH).o"

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

# ─── Ticket modules (Kerbeus-BOF) ───
# These modules share the Kerbeus-BOF library under tickets/_kerbeus_lib/
# and need its include path so the #include directives resolve correctly.

KERBEUS_INCLUDES = $(INCLUDES) -Itickets/_kerbeus_lib -Wno-incompatible-pointer-types -Wno-int-conversion

requesttgt:
	@mkdir -p tickets/requesttgt/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/requesttgt/bin/requesttgt.$(ARCH).o \
		tickets/requesttgt/src/requesttgt.c
	@echo "  [+] requesttgt.$(ARCH).o"

requesttgs:
	@mkdir -p tickets/requesttgs/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/requesttgs/bin/requesttgs.$(ARCH).o \
		tickets/requesttgs/src/requesttgs.c
	@echo "  [+] requesttgs.$(ARCH).o"

klist:
	@mkdir -p tickets/klist/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/klist/bin/klist.$(ARCH).o \
		tickets/klist/src/klist.c
	@echo "  [+] klist.$(ARCH).o"

# Note: "tickets_ptt" avoids collision with the credentials/ptt target.
tickets_ptt:
	@mkdir -p tickets/ptt/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/ptt/bin/ptt.$(ARCH).o \
		tickets/ptt/src/ptt.c
	@echo "  [+] tickets/ptt.$(ARCH).o"

purgetickets:
	@mkdir -p tickets/purgetickets/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/purgetickets/bin/purgetickets.$(ARCH).o \
		tickets/purgetickets/src/purgetickets.c
	@echo "  [+] purgetickets.$(ARCH).o"

tgtdeleg:
	@mkdir -p tickets/tgtdeleg/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/tgtdeleg/bin/tgtdeleg.$(ARCH).o \
		tickets/tgtdeleg/src/tgtdeleg.c
	@echo "  [+] tgtdeleg.$(ARCH).o"

describeticket:
	@mkdir -p tickets/describeticket/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/describeticket/bin/describeticket.$(ARCH).o \
		tickets/describeticket/src/describeticket.c
	@echo "  [+] describeticket.$(ARCH).o"

hash:
	@mkdir -p tickets/hash/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/hash/bin/hash.$(ARCH).o \
		tickets/hash/src/hash.c
	@echo "  [+] hash.$(ARCH).o"

renewticket:
	@mkdir -p tickets/renewticket/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/renewticket/bin/renewticket.$(ARCH).o \
		tickets/renewticket/src/renewticket.c
	@echo "  [+] renewticket.$(ARCH).o"

changepw:
	@mkdir -p tickets/changepw/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/changepw/bin/changepw.$(ARCH).o \
		tickets/changepw/src/changepw.c
	@echo "  [+] changepw.$(ARCH).o"

s4u:
	@mkdir -p tickets/s4u/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/s4u/bin/s4u.$(ARCH).o \
		tickets/s4u/src/s4u.c
	@echo "  [+] s4u.$(ARCH).o"


# ─── New Kerbeus ticket modules ───

cross_s4u:
	@mkdir -p tickets/cross_s4u/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/cross_s4u/bin/cross_s4u.$(ARCH).o \
		tickets/cross_s4u/src/cross_s4u.c
	@echo "  [+] cross_s4u.$(ARCH).o"

kerberoasting:
	@mkdir -p tickets/kerberoasting/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/kerberoasting/bin/kerberoasting.$(ARCH).o \
		tickets/kerberoasting/src/kerberoasting.c
	@echo "  [+] kerberoasting.$(ARCH).o"

asreproasting:
	@mkdir -p tickets/asreproasting/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) \
		-o tickets/asreproasting/bin/asreproasting.$(ARCH).o \
		tickets/asreproasting/src/asreproasting.c
	@echo "  [+] asreproasting.$(ARCH).o"

dump:
	@mkdir -p tickets/dump/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) -DDUMP \
		-o tickets/dump/bin/dump.$(ARCH).o \
		tickets/dump/src/dump.c
	@echo "  [+] dump.$(ARCH).o"

triage:
	@mkdir -p tickets/triage/bin
	$(CC) $(CFLAGS) $(KERBEUS_INCLUDES) -DTRIAGE \
		-o tickets/triage/bin/triage.$(ARCH).o \
		tickets/triage/src/triage.c
	@echo "  [+] triage.$(ARCH).o"

# ─── Utility modules ───

execute_assembly:
	@mkdir -p utility/execute_assembly/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o utility/execute_assembly/bin/execute_assembly.$(ARCH).o \
		utility/execute_assembly/src/execute_assembly.c
	@echo "  [+] execute_assembly.$(ARCH).o"

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

underlaycopy:
	@mkdir -p credentials/underlaycopy/bin
	$(CC) $(CFLAGS) $(INCLUDES) \
		-o credentials/underlaycopy/bin/underlaycopy.$(ARCH).o \
		credentials/underlaycopy/src/underlaycopy.c
	@echo "  [+] underlaycopy.$(ARCH).o"
