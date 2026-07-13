using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Agent.Interop;

namespace Agent.NativeModules
{
    /// <summary>
    /// Reports current user context, integrity level, privileges, and groups.
    /// Uses Win32 API — no child process spawned.
    /// </summary>
    public class WhoAmIModule : INativeModule
    {
        public string Name { get { return "whoami"; } }
        public string Description { get { return "Current user context, privileges, and group membership"; } }

        public byte[] Execute(byte[] arguments)
        {
            var sb = new StringBuilder();

            var identity = WindowsIdentity.GetCurrent();
            sb.AppendLine("Username:    " + identity.Name);
            sb.AppendLine("SID:         " + (identity.User != null ? identity.User.ToString() : "N/A"));

            // Integrity level
            sb.AppendLine("Integrity:   " + GetIntegrityLevel());

            // Admin check
            var principal = new WindowsPrincipal(identity);
            sb.AppendLine("Is Admin:    " + principal.IsInRole(WindowsBuiltInRole.Administrator));
            sb.AppendLine("Impersonation: " + identity.ImpersonationLevel);

            // Process info
            sb.AppendLine("PID:         " + System.Diagnostics.Process.GetCurrentProcess().Id);
            sb.AppendLine("Session ID:  " + System.Diagnostics.Process.GetCurrentProcess().SessionId);
            sb.AppendLine("Logon Server: " + Environment.GetEnvironmentVariable("LOGONSERVER"));

            // Privileges
            sb.AppendLine();
            sb.AppendLine("=== PRIVILEGES ===");
            EnumPrivileges(sb);

            // Groups
            sb.AppendLine();
            sb.AppendLine("=== GROUP MEMBERSHIP ===");
            if (identity.Groups != null)
            {
                foreach (var group in identity.Groups)
                {
                    try
                    {
                        var account = group.Translate(typeof(NTAccount));
                        sb.AppendLine("  " + account.Value);
                    }
                    catch
                    {
                        sb.AppendLine("  " + group.Value);
                    }
                }
            }

            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        private string GetIntegrityLevel()
        {
            IntPtr hToken;
            if (!Advapi32.OpenProcessToken(Kernel32.GetCurrentProcess(),
                Advapi32.TOKEN_QUERY, out hToken))
                return "UNKNOWN";

            try
            {
                uint retLen;
                Advapi32.GetTokenInformation(hToken, Advapi32.TokenIntegrityLevel,
                    IntPtr.Zero, 0, out retLen);

                IntPtr pTil = Marshal.AllocHGlobal((int)retLen);
                try
                {
                    if (!Advapi32.GetTokenInformation(hToken, Advapi32.TokenIntegrityLevel,
                        pTil, retLen, out retLen))
                        return "UNKNOWN";

                    IntPtr pSid = Marshal.ReadIntPtr(pTil);
                    int subAuthCount = Marshal.ReadByte(pSid, 1);
                    int offset = 8 + (subAuthCount - 1) * 4;
                    uint rid = (uint)Marshal.ReadInt32(pSid, offset);

                    if (rid >= 0x4000) return "SYSTEM";
                    if (rid >= 0x3000) return "HIGH";
                    if (rid >= 0x2000) return "MEDIUM";
                    return "LOW";
                }
                finally
                {
                    Marshal.FreeHGlobal(pTil);
                }
            }
            finally
            {
                Kernel32.CloseHandle(hToken);
            }
        }

        private void EnumPrivileges(StringBuilder sb)
        {
            IntPtr hToken;
            if (!Advapi32.OpenProcessToken(Kernel32.GetCurrentProcess(),
                Advapi32.TOKEN_QUERY, out hToken))
                return;

            try
            {
                uint retLen;
                Advapi32.GetTokenInformation(hToken, Advapi32.TokenPrivileges,
                    IntPtr.Zero, 0, out retLen);

                IntPtr pPrivs = Marshal.AllocHGlobal((int)retLen);
                try
                {
                    if (!Advapi32.GetTokenInformation(hToken, Advapi32.TokenPrivileges,
                        pPrivs, retLen, out retLen))
                        return;

                    uint privCount = (uint)Marshal.ReadInt32(pPrivs, 0);
                    int privOffset = 4; // After PrivilegeCount

                    for (uint i = 0; i < privCount; i++)
                    {
                        // LUID_AND_ATTRIBUTES: LUID(8B) + Attributes(4B) = 12 bytes
                        IntPtr pLuid = IntPtr.Add(pPrivs, privOffset);
                        uint attrs = (uint)Marshal.ReadInt32(pPrivs, privOffset + 8);

                        // Lookup privilege name
                        uint nameLen = 64;
                        var name = new StringBuilder((int)nameLen);
                        Advapi32.LookupPrivilegeNameW(null, pLuid, name, ref nameLen);

                        string status = (attrs & 0x02) != 0 ? "ENABLED" : "DISABLED";
                        sb.AppendFormat("  {0,-45} {1}", name.ToString(), status);
                        sb.AppendLine();

                        privOffset += 12;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pPrivs);
                }
            }
            finally
            {
                Kernel32.CloseHandle(hToken);
            }
        }
    }
}
