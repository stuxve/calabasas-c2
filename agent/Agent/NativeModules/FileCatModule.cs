using System;
using System.Text;
using Agent.Interop;

namespace Agent.NativeModules
{
    /// <summary>
    /// Read and display file contents using CreateFileW/ReadFile.
    /// </summary>
    public class FileCatModule : INativeModule
    {
        public string Name { get { return "cat"; } }
        public string Description { get { return "Display file contents"; } }

        private const uint MAX_READ_SIZE = 10 * 1024 * 1024; // 10MB limit

        public byte[] Execute(byte[] arguments)
        {
            if (arguments == null || arguments.Length == 0)
                return Encoding.UTF8.GetBytes("[!] Usage: cat <filepath>");

            string path = Encoding.UTF8.GetString(arguments).Trim('\0').Trim();

            IntPtr hFile = Kernel32.CreateFileW(
                path,
                Kernel32.GENERIC_READ,
                Kernel32.FILE_SHARE_READ,
                IntPtr.Zero,
                Kernel32.OPEN_EXISTING,
                0,
                IntPtr.Zero);

            if (hFile == Kernel32.INVALID_HANDLE_VALUE)
            {
                return Encoding.UTF8.GetBytes(string.Format(
                    "[!] Cannot open '{0}': error {1}",
                    path, System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
            }

            try
            {
                uint fileSize = Kernel32.GetFileSize(hFile, IntPtr.Zero);
                if (fileSize == 0xFFFFFFFF)
                    return Encoding.UTF8.GetBytes("[!] Cannot determine file size");

                if (fileSize > MAX_READ_SIZE)
                    return Encoding.UTF8.GetBytes(string.Format(
                        "[!] File too large ({0} bytes). Max: {1} bytes",
                        fileSize, MAX_READ_SIZE));

                byte[] buffer = new byte[fileSize];
                uint bytesRead;

                if (!Kernel32.ReadFile(hFile, buffer, fileSize, out bytesRead, IntPtr.Zero))
                {
                    return Encoding.UTF8.GetBytes(string.Format(
                        "[!] ReadFile failed: error {0}",
                        System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
                }

                // Return raw bytes (may be text or binary)
                byte[] result = new byte[bytesRead];
                Array.Copy(buffer, result, bytesRead);
                return result;
            }
            finally
            {
                Kernel32.CloseHandle(hFile);
            }
        }
    }
}
