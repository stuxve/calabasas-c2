using System;
using System.Collections.Generic;
using System.Text;

namespace Agent.Protocol
{
    /// <summary>
    /// Builds TLV (Type-Length-Value) byte sequences.
    /// Format: TYPE(2B LE) + LEN(4B LE) + VALUE(LEN bytes)
    /// </summary>
    public class TlvBuilder
    {
        private readonly List<byte> _buffer = new List<byte>();

        public void AddRaw(ushort type, byte[] value)
        {
            _buffer.AddRange(BitConverter.GetBytes(type));
            _buffer.AddRange(BitConverter.GetBytes((uint)value.Length));
            _buffer.AddRange(value);
        }

        public void AddString(ushort type, string value)
        {
            AddRaw(type, Encoding.UTF8.GetBytes(value));
        }

        public void AddUInt32(ushort type, uint value)
        {
            AddRaw(type, BitConverter.GetBytes(value));
        }

        public void AddUInt8(ushort type, byte value)
        {
            AddRaw(type, new[] { value });
        }

        public void AddUuid(ushort type, byte[] uuidBytes)
        {
            AddRaw(type, uuidBytes);
        }

        public byte[] Build()
        {
            return _buffer.ToArray();
        }
    }

    /// <summary>
    /// Parses TLV entries from a byte buffer.
    /// </summary>
    public static class TlvParser
    {
        public struct TlvEntry
        {
            public ushort Type;
            public byte[] Value;
        }

        public static List<TlvEntry> Parse(byte[] data, int offset, int length)
        {
            var entries = new List<TlvEntry>();
            int pos = offset;
            int end = offset + length;

            while (pos + 6 <= end)
            {
                ushort type = BitConverter.ToUInt16(data, pos);
                uint len = BitConverter.ToUInt32(data, pos + 2);

                if (pos + 6 + len > end) break;

                byte[] value = new byte[len];
                Array.Copy(data, pos + 6, value, 0, (int)len);

                entries.Add(new TlvEntry { Type = type, Value = value });
                pos += 6 + (int)len;
            }

            return entries;
        }

        public static byte[] FindValue(List<TlvEntry> entries, ushort type)
        {
            foreach (var e in entries)
            {
                if (e.Type == type) return e.Value;
            }
            return null;
        }

        public static string FindString(List<TlvEntry> entries, ushort type)
        {
            var val = FindValue(entries, type);
            return val != null ? Encoding.UTF8.GetString(val) : null;
        }

        public static uint? FindUInt32(List<TlvEntry> entries, ushort type)
        {
            var val = FindValue(entries, type);
            return val != null && val.Length >= 4 ? (uint?)BitConverter.ToUInt32(val, 0) : null;
        }
    }
}
