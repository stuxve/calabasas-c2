using System;
using System.Text;
using Agent.Interop;

namespace Agent.NativeModules
{
    /// <summary>
    /// List directory contents using FindFirstFileW/FindNextFileW.
    /// No child process spawned — direct Win32 API.
    /// </summary>
    public class FileListModule : INativeModule
    {
        public string Name { get { return "ls"; } }
        public string Description { get { return "List directory contents"; } }

        public byte[] Execute(byte[] arguments)
        {
            string path = ".";
            if (arguments != null && arguments.Length > 0)
            {
                path = Encoding.UTF8.GetString(arguments).Trim('\0').Trim();
            }

            if (string.IsNullOrEmpty(path)) path = ".";

            // Ensure path ends with \* for FindFirstFile
            string searchPath = path;
            if (!searchPath.EndsWith("\\*") && !searchPath.EndsWith("/*"))
            {
                searchPath = searchPath.TrimEnd('\\', '/') + "\\*";
            }

            var sb = new StringBuilder();
            sb.AppendFormat("Directory: {0}", path);
            sb.AppendLine();
            sb.AppendLine();
            sb.AppendFormat("{0,-12} {1,-20} {2,-14} {3}",
                "Type", "LastWriteTime", "Size", "Name");
            sb.AppendLine();
            sb.AppendLine(new string('-', 60));

            Kernel32.WIN32_FIND_DATA findData;
            IntPtr hFind = Kernel32.FindFirstFileW(searchPath, out findData);

            if (hFind == Kernel32.INVALID_HANDLE_VALUE)
            {
                return Encoding.UTF8.GetBytes(
                    string.Format("[!] Cannot access '{0}': error {1}",
                        path, System.Runtime.InteropServices.Marshal.GetLastWin32Error()));
            }

            try
            {
                do
                {
                    string name = findData.cFileName;
                    if (name == "." || name == "..") continue;

                    bool isDir = (findData.dwFileAttributes & 0x10) != 0;
                    string type = isDir ? "<DIR>" : "";
                    long size = ((long)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;
                    string sizeStr = isDir ? "" : FormatSize(size);

                    // Convert FILETIME to DateTime
                    long ft = ((long)findData.ftLastWriteTime.dwHighDateTime << 32) |
                              (uint)findData.ftLastWriteTime.dwLowDateTime;
                    DateTime lastWrite = DateTime.FromFileTime(ft);

                    sb.AppendFormat("{0,-12} {1,-20} {2,-14} {3}",
                        type,
                        lastWrite.ToString("yyyy-MM-dd HH:mm"),
                        sizeStr,
                        name);
                    sb.AppendLine();

                } while (Kernel32.FindNextFileW(hFind, out findData));
            }
            finally
            {
                Kernel32.FindClose(hFind);
            }

            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024) + " KB";
            if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)) + " MB";
            return (bytes / (1024 * 1024 * 1024)) + " GB";
        }
    }
}
