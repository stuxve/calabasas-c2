/*
 * hash.c — calabasas-c2 BOF wrapper for Kerbeus-BOF hash.
 * Calculates RC4, AES128, and AES256 Kerberos keys from a password.
 */
#include "../_kerbeus_lib/functions.c"
#include "../_kerbeus_lib/crypt_key.c"


void GenerateHashes(char* user, char* domain, char* password) {
    PRINT_OUT("[*] Input Password           : %s\n", password);
    if (user && domain) {
        PRINT_OUT("[*] Input Username           : %s\n", user);
        PRINT_OUT("[*] Input Domain             : %s\n", domain);
    }

    int   rc4_hash_size = 0;
    byte* rc4_hash = 0;
    if (!get_key_rc4(password, &rc4_hash, &rc4_hash_size)) {
        int hexHashLength = rc4_hash_size * 2 + 1;
        char* hex_hash = MemAlloc(hexHashLength);
        my_tohex(rc4_hash, rc4_hash_size, &hex_hash, hexHashLength);
        PRINT_OUT("[*]     rc4_hmac             : %s\n", hex_hash);
    }
    if (user && domain) {
        int   aes128_hash_size = 0;
        byte* aes128_hash = 0;
        if (!get_key_aes128(domain, user, password, &aes128_hash, &aes128_hash_size)) {
            int hexHashLength = aes128_hash_size * 2 + 1;
            char* hex_hash = MemAlloc(hexHashLength);
            my_tohex(aes128_hash, aes128_hash_size, &hex_hash, hexHashLength);
            PRINT_OUT("[*]     aes128_cts_hmac_sha1 : %s\n", hex_hash);
        }

        int   aes256_hash_size = 0;
        byte* aes256_hash = 0;
        if (!get_key_aes256(domain, user, password, &aes256_hash, &aes256_hash_size)) {
            int hexHashLength = aes256_hash_size * 2 + 1;
            char* hex_hash = MemAlloc(hexHashLength);
            my_tohex(aes256_hash, aes256_hash_size, &hex_hash, hexHashLength);
            PRINT_OUT("[*]     aes256_cts_hmac_sha1 : %s\n", hex_hash);
        }
    }
}

void HASH_RUN( PCHAR Buffer, IN DWORD Length ) {
    PRINT_OUT("[*] Action: Calculate Password Hash(es)\n\n");

    char* user = NULL;
    char* domain = NULL;
    char* password = NULL;

    for (int i = 0; i < Length; i++) {
        i += GetStrParam(Buffer + i, Length - i, "/user:", 6, &user );
        i += GetStrParam(Buffer + i, Length - i, "/domain:", 8, &domain );
        i += GetStrParam(Buffer + i, Length - i, "/password:", 10, &password );
    }

    if (password)
        GenerateHashes(user, domain, password);
    else
        PRINT_OUT("[X] /password:X must be supplied!\n");
}


/* ─── calabasas-c2 entry point ─── */
VOID go(IN PCHAR Buffer, IN ULONG Length) {
    INIT_BOF();

    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    int sz = 0;
    char* user     = BeaconDataExtract(&parser, &sz);
    char* domain   = BeaconDataExtract(&parser, &sz);
    char* password = BeaconDataExtract(&parser, &sz);

    char cmdBuf[2048];
    int  pos = 0;

    if (user && user[0])         pos += MSVCRT$sprintf(cmdBuf + pos, "/user:%s ", user);
    if (domain && domain[0])     pos += MSVCRT$sprintf(cmdBuf + pos, "/domain:%s ", domain);
    if (password && password[0]) pos += MSVCRT$sprintf(cmdBuf + pos, "/password:%s ", password);

    if (pos > 0) cmdBuf[pos - 1] = '\0';
    else cmdBuf[0] = '\0';

    if (LoadFunc())
        PRINT_OUT("%s\n", "Modules not loaded");
    else
        HASH_RUN(cmdBuf, pos);

    FreeBank();
    END_BOF();
}
