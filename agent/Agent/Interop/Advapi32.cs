using System;
using System.Runtime.InteropServices;

namespace Agent.Interop
{
    /// <summary>
    /// P/Invoke declarations for advapi32.dll.
    /// </summary>
    public static class Advapi32
    {
        // Token constants
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_IMPERSONATE = 0x0004;

        // Token information classes
        public const uint TokenUser = 1;
        public const uint TokenGroups = 2;
        public const uint TokenPrivileges = 3;
        public const uint TokenIntegrityLevel = 25;

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle,
            uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenThreadToken(IntPtr ThreadHandle,
            uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        /// <summary>
        /// Get the effective token — thread impersonation token if present,
        /// otherwise the process token. Use this everywhere the "current identity"
        /// matters (whoami, privilege checks, etc.).
        /// </summary>
        public static bool OpenEffectiveToken(uint desiredAccess, out IntPtr hToken)
        {
            // Try thread token first (set by ImpersonateLoggedOnUser / getsystem)
            if (OpenThreadToken(Kernel32.GetCurrentThread(), desiredAccess, false, out hToken))
                return true;

            // No impersonation — fall back to process token
            return OpenProcessToken(Kernel32.GetCurrentProcess(), desiredAccess, out hToken);
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle,
            uint TokenInformationClass, IntPtr TokenInformation,
            uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeNameW(string lpSystemName,
            IntPtr lpLuid, System.Text.StringBuilder lpName, ref uint cchName);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupAccountSidW(string lpSystemName,
            IntPtr Sid, System.Text.StringBuilder lpName, ref uint cchName,
            System.Text.StringBuilder lpReferencedDomainName, ref uint cchReferencedDomainName,
            out uint peUse);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken,
            uint dwDesiredAccess, IntPtr lpTokenAttributes,
            int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        // Registry
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int RegOpenKeyExW(IntPtr hKey, string lpSubKey,
            uint ulOptions, uint samDesired, out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern int RegQueryValueExW(IntPtr hKey, string lpValueName,
            IntPtr lpReserved, out uint lpType, byte[] lpData, ref uint lpcbData);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(IntPtr hKey);

        // Registry hive roots
        public static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));
        public static readonly IntPtr HKEY_CURRENT_USER = new IntPtr(unchecked((int)0x80000001));

        public const uint KEY_READ = 0x20019;
    }
}
