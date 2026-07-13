using System;

namespace Agent.Protocol
{
    /// <summary>
    /// Handles packet framing: MAGIC(4B) + SIZE(4B) + MSG_ID(4B) + PAYLOAD
    /// </summary>
    public static class PacketFramer
    {
        public static byte[] Pack(byte[] encryptedPayload, uint msgId, uint magic)
        {
            uint totalSize = (uint)(Constants.HEADER_SIZE + encryptedPayload.Length);
            byte[] packet = new byte[totalSize];

            Array.Copy(BitConverter.GetBytes(magic), 0, packet, 0, 4);
            Array.Copy(BitConverter.GetBytes(totalSize), 0, packet, 4, 4);
            Array.Copy(BitConverter.GetBytes(msgId), 0, packet, 8, 4);
            Array.Copy(encryptedPayload, 0, packet, Constants.HEADER_SIZE, encryptedPayload.Length);

            return packet;
        }

        public static bool TryUnpack(byte[] data, uint expectedMagic,
            out uint msgId, out byte[] payload)
        {
            msgId = 0;
            payload = null;

            if (data == null || data.Length < Constants.HEADER_SIZE) return false;

            uint magic = BitConverter.ToUInt32(data, 0);
            if (magic != expectedMagic) return false;

            uint size = BitConverter.ToUInt32(data, 4);
            if (size > data.Length) return false;

            msgId = BitConverter.ToUInt32(data, 8);

            int payloadLen = (int)size - Constants.HEADER_SIZE;
            if (payloadLen <= 0) return false;

            payload = new byte[payloadLen];
            Array.Copy(data, Constants.HEADER_SIZE, payload, 0, payloadLen);
            return true;
        }

        /// <summary>
        /// Pack a decrypted command: CMD(1B) + BODY_LEN(4B) + BODY
        /// </summary>
        public static byte[] PackCommand(byte cmd, byte[] body)
        {
            byte[] result = new byte[5 + body.Length];
            result[0] = cmd;
            Array.Copy(BitConverter.GetBytes((uint)body.Length), 0, result, 1, 4);
            Array.Copy(body, 0, result, 5, body.Length);
            return result;
        }

        /// <summary>
        /// Unpack a decrypted command.
        /// </summary>
        public static bool TryUnpackCommand(byte[] plaintext, out byte cmd, out byte[] body)
        {
            cmd = 0;
            body = null;

            if (plaintext == null || plaintext.Length < 5) return false;

            cmd = plaintext[0];
            uint bodyLen = BitConverter.ToUInt32(plaintext, 1);

            if (5 + bodyLen > plaintext.Length) return false;

            body = new byte[bodyLen];
            Array.Copy(plaintext, 5, body, 0, (int)bodyLen);
            return true;
        }
    }
}
