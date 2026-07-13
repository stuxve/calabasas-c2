/*
 * crypto.c — AES-256-GCM, ECDH P-256, HKDF-SHA256, RSA-OAEP via Windows BCrypt.
 * Requires Windows 8.1+ for BCRYPT_KDF_RAW_SECRET.
 */
#include "agent.h"

/* Algorithm handles (opened once, reused) */
static BCRYPT_ALG_HANDLE g_hAes = NULL;
static BCRYPT_ALG_HANDLE g_hEcdh = NULL;
static BCRYPT_ALG_HANDLE g_hRsa = NULL;
static BCRYPT_ALG_HANDLE g_hSha256 = NULL;   /* plain hash */
static BCRYPT_ALG_HANDLE g_hHmac = NULL;      /* HMAC-SHA256 */

BOOL crypto_init(void) {
    NTSTATUS s;

    /* AES in GCM mode */
    s = BCryptOpenAlgorithmProvider(&g_hAes, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) return FALSE;
    s = BCryptSetProperty(g_hAes, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(s)) return FALSE;

    /* ECDH P-256 */
    s = BCryptOpenAlgorithmProvider(&g_hEcdh, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) return FALSE;

    /* RSA */
    s = BCryptOpenAlgorithmProvider(&g_hRsa, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) return FALSE;

    /* SHA-256 (plain) */
    s = BCryptOpenAlgorithmProvider(&g_hSha256, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) return FALSE;

    /* HMAC-SHA256 */
    s = BCryptOpenAlgorithmProvider(&g_hHmac, BCRYPT_SHA256_ALGORITHM, NULL,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(s)) return FALSE;

    return TRUE;
}

void crypto_cleanup(void) {
    if (g_hAes)    BCryptCloseAlgorithmProvider(g_hAes, 0);
    if (g_hEcdh)   BCryptCloseAlgorithmProvider(g_hEcdh, 0);
    if (g_hRsa)    BCryptCloseAlgorithmProvider(g_hRsa, 0);
    if (g_hSha256) BCryptCloseAlgorithmProvider(g_hSha256, 0);
    if (g_hHmac)   BCryptCloseAlgorithmProvider(g_hHmac, 0);
}

/* ─── AES-256-GCM ─── */

/*
 * Encrypt: returns NONCE(12) + CIPHERTEXT + TAG(16).
 * Caller frees *out.
 */
BOOL aes_gcm_encrypt(const unsigned char *key, const unsigned char *nonce,
                     const unsigned char *plaintext, DWORD pt_len,
                     unsigned char **out, DWORD *out_len) {
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS s;
    BOOL result = FALSE;

    s = BCryptGenerateSymmetricKey(g_hAes, &hKey, NULL, 0,
                                   (PUCHAR)key, KEY_SIZE, 0);
    if (!NT_SUCCESS(s)) return FALSE;

    /* Output: nonce(12) + ciphertext(pt_len) + tag(16) */
    DWORD total = NONCE_SIZE + pt_len + TAG_SIZE;
    *out = (unsigned char *)malloc(total);
    *out_len = total;

    memcpy(*out, nonce, NONCE_SIZE);

    unsigned char tag[TAG_SIZE];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = NONCE_SIZE;
    authInfo.pbTag = tag;
    authInfo.cbTag = TAG_SIZE;

    ULONG written;
    s = BCryptEncrypt(hKey, (PUCHAR)plaintext, pt_len, &authInfo,
                      NULL, 0, *out + NONCE_SIZE, pt_len, &written, 0);
    if (NT_SUCCESS(s)) {
        memcpy(*out + NONCE_SIZE + pt_len, tag, TAG_SIZE);
        result = TRUE;
    } else {
        free(*out);
        *out = NULL;
        *out_len = 0;
    }

    BCryptDestroyKey(hKey);
    return result;
}

/*
 * Decrypt: input is NONCE(12) + CIPHERTEXT + TAG(16).
 * Caller frees *out.
 */
BOOL aes_gcm_decrypt(const unsigned char *key,
                     const unsigned char *data, DWORD data_len,
                     unsigned char **out, DWORD *out_len) {
    if (data_len < NONCE_SIZE + TAG_SIZE) return FALSE;

    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS s;
    BOOL result = FALSE;

    s = BCryptGenerateSymmetricKey(g_hAes, &hKey, NULL, 0,
                                   (PUCHAR)key, KEY_SIZE, 0);
    if (!NT_SUCCESS(s)) return FALSE;

    const unsigned char *nonce = data;
    DWORD ct_len = data_len - NONCE_SIZE - TAG_SIZE;
    const unsigned char *ciphertext = data + NONCE_SIZE;
    const unsigned char *tag = data + NONCE_SIZE + ct_len;

    *out = (unsigned char *)malloc(ct_len + 1);
    *out_len = ct_len;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = NONCE_SIZE;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = TAG_SIZE;

    ULONG written;
    s = BCryptDecrypt(hKey, (PUCHAR)ciphertext, ct_len, &authInfo,
                      NULL, 0, *out, ct_len, &written, 0);
    if (NT_SUCCESS(s)) {
        (*out)[written] = '\0';
        *out_len = written;
        result = TRUE;
    } else {
        free(*out);
        *out = NULL;
        *out_len = 0;
    }

    BCryptDestroyKey(hKey);
    return result;
}

/* ─── Nonce management ─── */

void make_nonce(const unsigned char *agent_id_prefix, ULONGLONG counter,
                unsigned char *nonce_out) {
    memcpy(nonce_out, agent_id_prefix, 4);
    memcpy(nonce_out + 4, &counter, 8);  /* LE — native x86 */
}

/* ─── HMAC-SHA256 ─── */

BOOL hmac_sha256(const unsigned char *key, DWORD key_len,
                 const unsigned char *data, DWORD data_len,
                 unsigned char *out) {
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS s;

    s = BCryptCreateHash(g_hHmac, &hHash, NULL, 0,
                         (PUCHAR)key, key_len, 0);
    if (!NT_SUCCESS(s)) return FALSE;

    s = BCryptHashData(hHash, (PUCHAR)data, data_len, 0);
    if (!NT_SUCCESS(s)) { BCryptDestroyHash(hHash); return FALSE; }

    s = BCryptFinishHash(hHash, out, 32, 0);
    BCryptDestroyHash(hHash);
    return NT_SUCCESS(s);
}

/* ─── HKDF-SHA256 ─── */

BOOL hkdf_sha256(const unsigned char *ikm, DWORD ikm_len,
                 const unsigned char *salt, DWORD salt_len,
                 const unsigned char *info, DWORD info_len,
                 unsigned char *okm, DWORD okm_len) {
    unsigned char prk[32];

    /* Extract: PRK = HMAC-SHA256(salt, IKM) */
    if (!hmac_sha256(salt, salt_len, ikm, ikm_len, prk))
        return FALSE;

    /* Expand: T(1) = HMAC-SHA256(PRK, info || 0x01) */
    /* For 32-byte output, we only need one block */
    if (okm_len > 32) return FALSE;  /* Only support single block */

    unsigned char expand_input[256];
    DWORD expand_len = 0;
    if (info && info_len > 0) {
        memcpy(expand_input, info, info_len);
        expand_len = info_len;
    }
    expand_input[expand_len++] = 0x01;

    unsigned char t1[32];
    if (!hmac_sha256(prk, 32, expand_input, expand_len, t1))
        return FALSE;

    memcpy(okm, t1, okm_len);
    SecureZeroMemory(prk, 32);
    return TRUE;
}

/* ─── ECDH P-256 ─── */

BOOL ecdh_generate_keypair(unsigned char *pub_out, BCRYPT_KEY_HANDLE *priv_out) {
    NTSTATUS s;

    s = BCryptGenerateKeyPair(g_hEcdh, priv_out, 256, 0);
    if (!NT_SUCCESS(s)) return FALSE;

    s = BCryptFinalizeKeyPair(*priv_out, 0);
    if (!NT_SUCCESS(s)) return FALSE;

    /* Export public key → BCRYPT_ECCPUBLIC_BLOB: header(8) + X(32) + Y(32) */
    ULONG blob_size;
    s = BCryptExportKey(*priv_out, NULL, BCRYPT_ECCPUBLIC_BLOB,
                        NULL, 0, &blob_size, 0);
    if (!NT_SUCCESS(s)) return FALSE;

    unsigned char *blob = (unsigned char *)malloc(blob_size);
    s = BCryptExportKey(*priv_out, NULL, BCRYPT_ECCPUBLIC_BLOB,
                        blob, blob_size, &blob_size, 0);
    if (!NT_SUCCESS(s)) { free(blob); return FALSE; }

    /* Convert to uncompressed point: 0x04 + X(32) + Y(32) */
    pub_out[0] = 0x04;
    memcpy(pub_out + 1, blob + 8, 64);  /* Skip 8-byte BCRYPT_ECCKEY_BLOB header */
    free(blob);
    return TRUE;
}

BOOL ecdh_derive_shared_secret(BCRYPT_KEY_HANDLE priv_key,
                               const unsigned char *peer_pub,
                               unsigned char *secret_out) {
    NTSTATUS s;

    /* Import peer public key: build BCRYPT_ECCPUBLIC_BLOB */
    /* Header: magic(4) = BCRYPT_ECDH_PUBLIC_P256_MAGIC, cbKey(4) = 32 */
    unsigned char blob[72]; /* 8 header + 32 X + 32 Y */
    DWORD magic_val = 0x314B4345; /* ECK1 */
    DWORD cbKey = 32;
    memcpy(blob, &magic_val, 4);
    memcpy(blob + 4, &cbKey, 4);
    memcpy(blob + 8, peer_pub + 1, 64);  /* Skip 0x04 prefix */

    BCRYPT_KEY_HANDLE hPeerKey = NULL;
    s = BCryptImportKeyPair(g_hEcdh, NULL, BCRYPT_ECCPUBLIC_BLOB,
                            &hPeerKey, blob, 72, 0);
    if (!NT_SUCCESS(s)) return FALSE;

    /* Secret agreement */
    BCRYPT_SECRET_HANDLE hSecret = NULL;
    s = BCryptSecretAgreement(priv_key, hPeerKey, &hSecret, 0);
    if (!NT_SUCCESS(s)) {
        BCryptDestroyKey(hPeerKey);
        return FALSE;
    }

    /* Derive raw secret (Windows 8.1+ required) */
    ULONG secret_len;
    s = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL,
                        secret_out, 32, &secret_len, 0);
    BCryptDestroySecret(hSecret);
    BCryptDestroyKey(hPeerKey);

    if (!NT_SUCCESS(s)) return FALSE;

    /*
     * BCrypt returns the raw ECDH secret in LITTLE-ENDIAN byte order.
     * Python's cryptography library returns it in BIG-ENDIAN (SEC 1).
     * We must reverse the bytes to get matching key derivation.
     */
    for (int i = 0; i < 16; i++) {
        unsigned char tmp = secret_out[i];
        secret_out[i] = secret_out[31 - i];
        secret_out[31 - i] = tmp;
    }

    return TRUE;
}

void ecdh_free_key(BCRYPT_KEY_HANDLE key) {
    if (key) BCryptDestroyKey(key);
}

/* ─── RSA-OAEP-SHA256 encrypt ─── */

BOOL rsa_encrypt(const unsigned char *modulus, DWORD mod_len,
                 const unsigned char *exponent, DWORD exp_len,
                 const unsigned char *plaintext, DWORD pt_len,
                 unsigned char **out, DWORD *out_len) {
    NTSTATUS s;

    /*
     * Build BCRYPT_RSAPUBLIC_BLOB:
     *   BCRYPT_RSAKEY_BLOB header (24 bytes):
     *     Magic(4) = 0x31415352 ("RSA1")
     *     BitLength(4) = mod_len * 8
     *     cbPublicExp(4) = exp_len
     *     cbModulus(4) = mod_len
     *     cbPrime1(4) = 0
     *     cbPrime2(4) = 0
     *   Exponent[exp_len]
     *   Modulus[mod_len]
     */
    DWORD blob_size = 24 + exp_len + mod_len;
    unsigned char *blob = (unsigned char *)calloc(1, blob_size);

    DWORD rsa_magic = 0x31415352;  /* RSA1 */
    DWORD bit_len = mod_len * 8;
    memcpy(blob + 0, &rsa_magic, 4);
    memcpy(blob + 4, &bit_len, 4);
    memcpy(blob + 8, &exp_len, 4);
    memcpy(blob + 12, &mod_len, 4);
    /* cbPrime1 and cbPrime2 are 0 (already zeroed) */
    memcpy(blob + 24, exponent, exp_len);
    memcpy(blob + 24 + exp_len, modulus, mod_len);

    BCRYPT_KEY_HANDLE hPubKey = NULL;
    s = BCryptImportKeyPair(g_hRsa, NULL, BCRYPT_RSAPUBLIC_BLOB,
                            &hPubKey, blob, blob_size, 0);
    free(blob);
    if (!NT_SUCCESS(s)) return FALSE;

    /* Get output size */
    BCRYPT_OAEP_PADDING_INFO paddingInfo;
    paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    paddingInfo.pbLabel = NULL;
    paddingInfo.cbLabel = 0;

    ULONG cb_result;
    s = BCryptEncrypt(hPubKey, (PUCHAR)plaintext, pt_len, &paddingInfo,
                      NULL, 0, NULL, 0, &cb_result, BCRYPT_PAD_OAEP);
    if (!NT_SUCCESS(s)) { BCryptDestroyKey(hPubKey); return FALSE; }

    *out = (unsigned char *)malloc(cb_result);
    s = BCryptEncrypt(hPubKey, (PUCHAR)plaintext, pt_len, &paddingInfo,
                      NULL, 0, *out, cb_result, out_len, BCRYPT_PAD_OAEP);
    BCryptDestroyKey(hPubKey);

    if (!NT_SUCCESS(s)) {
        free(*out);
        *out = NULL;
        *out_len = 0;
        return FALSE;
    }
    return TRUE;
}
