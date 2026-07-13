using System;
using System.Runtime.InteropServices;

namespace Agent.Interop
{
    /// <summary>
    /// P/Invoke declarations for ntdll.dll.
    /// </summary>
    public static class Ntdll
    {
        public const uint SystemProcessInformation = 0x05;

        [DllImport("ntdll.dll")]
        public static extern uint NtQuerySystemInformation(
            uint SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);

        // NTSTATUS codes
        public const uint STATUS_SUCCESS = 0;
        public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

        // UNICODE_STRING
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }
    }
}
