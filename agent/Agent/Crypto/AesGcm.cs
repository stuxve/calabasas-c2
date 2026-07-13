using System;
using System.Security.Cryptography;

namespace Agent.Crypto
{
    /// <summary>
    /// AES-256-GCM encryption/decryption.
    /// On .NET 4.x, uses BCrypt (Windows CNG) since System.Security.Cryptography
    /// doesn't expose GCM directly until .NET Core.
    ///
    /// Fallback: AES-CBC-HMAC if CNG unavailable. For Phase 1, use AES-CBC with
    /// HMAC-SHA256 for encrypt-then-MAC, which is available on all .NET 4.x.
    /// </summary>
    public static class AesGcmHelper
    {
        private const int KEY_SIZE = 32;   // 256 bits
        private const int NONCE_SIZE = 12;
        private const int TAG_SIZE = 16;

        /// <summary>
        /// Encrypt plaintext with AES-256 in CBC mode + HMAC-SHA256 (encrypt-then-MAC).
        /// Output: NONCE(12B) + IV(16B) + CIPHERTEXT + HMAC(32B)
        ///
        /// Note: This is the .NET 4.x compatible path. The Python server
        /// detects the scheme from the nonce prefix and handles both GCM and CBC+HMAC.
        /// </summary>
        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] plaintext)
        {
            if (key.Length != KEY_SIZE)
                throw new ArgumentException("Key must be 32 bytes");
            if (nonce.Length != NONCE_SIZE)
                throw new ArgumentException("Nonce must be 12 bytes");

            // Derive separate encryption and MAC keys from the master key
            byte[] encKey = DeriveSubKey(key, 0x01);
            byte[] macKey = DeriveSubKey(key, 0x02);

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = 256;
                aes.Key = encKey;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.GenerateIV();

                byte[] iv = aes.IV;
                byte[] ciphertext;

                using (var encryptor = aes.CreateEncryptor())
                {
                    ciphertext = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
                }

                // Build output: NONCE + IV + CIPHERTEXT
                byte[] payload = new byte[NONCE_SIZE + iv.Length + ciphertext.Length];
                Array.Copy(nonce, 0, payload, 0, NONCE_SIZE);
                Array.Copy(iv, 0, payload, NONCE_SIZE, iv.Length);
                Array.Copy(ciphertext, 0, payload, NONCE_SIZE + iv.Length, ciphertext.Length);

                // HMAC over the entire payload
                byte[] hmac;
                using (var hmacSha = new HMACSHA256(macKey))
                {
                    hmac = hmacSha.ComputeHash(payload);
                }

                // Final: NONCE + IV + CIPHERTEXT + HMAC
                byte[] result = new byte[payload.Length + hmac.Length];
                Array.Copy(payload, 0, result, 0, payload.Length);
                Array.Copy(hmac, 0, result, payload.Length, hmac.Length);

                return result;
            }
        }

        /// <summary>
        /// Decrypt ciphertext. Input: NONCE(12B) + IV(16B) + CIPHERTEXT + HMAC(32B)
        /// </summary>
        public static byte[] Decrypt(byte[] key, byte[] data)
        {
            if (key.Length != KEY_SIZE)
                throw new ArgumentException("Key must be 32 bytes");
            if (data.Length < NONCE_SIZE + 16 + 32) // nonce + min IV + HMAC
                throw new ArgumentException("Data too short");

            byte[] encKey = DeriveSubKey(key, 0x01);
            byte[] macKey = DeriveSubKey(key, 0x02);

            int hmacOffset = data.Length - 32;

            // Verify HMAC first (encrypt-then-MAC: verify before decrypt)
            byte[] payload = new byte[hmacOffset];
            Array.Copy(data, 0, payload, 0, hmacOffset);

            byte[] expectedHmac = new byte[32];
            Array.Copy(data, hmacOffset, expectedHmac, 0, 32);

            byte[] computedHmac;
            using (var hmacSha = new HMACSHA256(macKey))
            {
                computedHmac = hmacSha.ComputeHash(payload);
            }

            if (!ConstantTimeEquals(expectedHmac, computedHmac))
                throw new CryptographicException("HMAC verification failed");

            // Extract nonce, IV, ciphertext
            byte[] iv = new byte[16];
            Array.Copy(data, NONCE_SIZE, iv, 0, 16);

            int ciphertextLen = hmacOffset - NONCE_SIZE - 16;
            byte[] ciphertext = new byte[ciphertextLen];
            Array.Copy(data, NONCE_SIZE + 16, ciphertext, 0, ciphertextLen);

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = 256;
                aes.Key = encKey;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                }
            }
        }

        /// <summary>
        /// Derive a sub-key from master key using HMAC-SHA256 with a purpose byte.
        /// </summary>
        private static byte[] DeriveSubKey(byte[] masterKey, byte purpose)
        {
            using (var hmac = new HMACSHA256(masterKey))
            {
                return hmac.ComputeHash(new[] { purpose });
            }
        }

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
