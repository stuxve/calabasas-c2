/*
 * Minimal test — same compiler flags as agent (-Wl,-e,main, --subsystem,windows).
 * Uses ONLY Win32 APIs — no CRT (fopen/fprintf won't work without CRT init).
 */
#include <windows.h>

int main(void) {
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\Temp\\minimal_test.log",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, "minimal test OK\r\n", 17, &written, NULL);
        CloseHandle(hFile);
    }

    Sleep(3000);
    return 0;
}
