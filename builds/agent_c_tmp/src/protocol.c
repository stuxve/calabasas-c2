/*
 * protocol.c — TLV builder/parser and packet framing.
 *
 * TLV wire format: TYPE(2B LE) + LEN(4B LE) + VALUE(LEN bytes)
 * Packet frame:    MAGIC(4B LE) + SIZE(4B LE) + MSG_ID(4B LE) + PAYLOAD
 * Command layer:   CMD(1B) + BODY_LEN(4B LE) + BODY
 */
#include "agent.h"

/* ─── TLV builder ─── */

void tlv_add_raw(Buffer *b, USHORT type, const void *value, DWORD len) {
    USHORT t = type;
    DWORD l = len;
    buf_append(b, &t, 2);
    buf_append(b, &l, 4);
    if (len > 0 && value)
        buf_append(b, value, len);
}

void tlv_add_string(Buffer *b, USHORT type, const char *str) {
    tlv_add_raw(b, type, str, (DWORD)strlen(str));
}

void tlv_add_uint32(Buffer *b, USHORT type, DWORD value) {
    tlv_add_raw(b, type, &value, 4);
}

void tlv_add_uint8(Buffer *b, USHORT type, BYTE value) {
    tlv_add_raw(b, type, &value, 1);
}

void tlv_add_uuid(Buffer *b, USHORT type, const unsigned char *uuid) {
    tlv_add_raw(b, type, uuid, UUID_SIZE);
}

/* ─── TLV parser ─── */

BOOL tlv_iter(const unsigned char *data, DWORD data_len, DWORD *offset, TlvEntry *entry) {
    if (*offset + 6 > data_len)
        return FALSE;

    memcpy(&entry->type, data + *offset, 2);
    memcpy(&entry->length, data + *offset + 2, 4);
    *offset += 6;

    if (*offset + entry->length > data_len)
        return FALSE;

    entry->value = data + *offset;
    *offset += entry->length;
    return TRUE;
}

const unsigned char *tlv_find(const unsigned char *data, DWORD data_len,
                              USHORT type, DWORD *out_len) {
    DWORD offset = 0;
    TlvEntry entry;
    while (tlv_iter(data, data_len, &offset, &entry)) {
        if (entry.type == type) {
            if (out_len) *out_len = entry.length;
            return entry.value;
        }
    }
    if (out_len) *out_len = 0;
    return NULL;
}

DWORD tlv_find_uint32(const unsigned char *data, DWORD data_len,
                      USHORT type, DWORD default_val) {
    DWORD len;
    const unsigned char *v = tlv_find(data, data_len, type, &len);
    if (v && len >= 4) {
        DWORD val;
        memcpy(&val, v, 4);
        return val;
    }
    return default_val;
}

BYTE tlv_find_uint8(const unsigned char *data, DWORD data_len,
                    USHORT type, BYTE default_val) {
    DWORD len;
    const unsigned char *v = tlv_find(data, data_len, type, &len);
    if (v && len >= 1) return v[0];
    return default_val;
}

const char *tlv_find_string(const unsigned char *data, DWORD data_len, USHORT type) {
    DWORD len;
    const unsigned char *v = tlv_find(data, data_len, type, &len);
    if (!v || len == 0) return NULL;
    /* Allocate and null-terminate — caller must free */
    char *str = (char *)malloc(len + 1);
    memcpy(str, v, len);
    str[len] = '\0';
    return str;
}

/* ─── Packet framing ─── */

void packet_pack(Buffer *out, const unsigned char *encrypted, DWORD enc_len,
                 DWORD msg_id, DWORD magic) {
    DWORD size = HEADER_SIZE + enc_len;
    buf_append(out, &magic, 4);
    buf_append(out, &size, 4);
    buf_append(out, &msg_id, 4);
    buf_append(out, encrypted, enc_len);
}

BOOL packet_unpack_header(const unsigned char *data, DWORD data_len,
                          DWORD *magic, DWORD *size, DWORD *msg_id) {
    if (data_len < HEADER_SIZE) return FALSE;
    memcpy(magic, data, 4);
    memcpy(size, data + 4, 4);
    memcpy(msg_id, data + 8, 4);
    return TRUE;
}

/* ─── Command layer ─── */

void command_pack(Buffer *out, BYTE cmd, const unsigned char *body, DWORD body_len) {
    buf_append(out, &cmd, 1);
    buf_append(out, &body_len, 4);
    if (body_len > 0 && body)
        buf_append(out, body, body_len);
}

BOOL command_unpack(const unsigned char *data, DWORD data_len,
                    BYTE *cmd, const unsigned char **body, DWORD *body_len) {
    if (data_len < 5) return FALSE;
    *cmd = data[0];
    memcpy(body_len, data + 1, 4);
    *body = data + 5;
    if (5 + *body_len > data_len) return FALSE;
    return TRUE;
}
