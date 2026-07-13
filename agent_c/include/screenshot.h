/*
 * screenshot.h — Desktop screenshot capture for pentest evidence.
 *
 * Captures the current desktop as a bitmap for documenting:
 *   - Proof of access (shows logged-in user's desktop)
 *   - Application state during assessment
 *   - Evidence for pentest reports
 *
 * Uses GDI BitBlt — no child processes, no external tools.
 */
#ifndef SCREENSHOT_H
#define SCREENSHOT_H

#include <windows.h>

/* ─── Screenshot options ─── */
typedef struct _SCREENSHOT_OPTS {
    int  monitor;      /* -1 = all monitors (virtual screen), 0+ = specific monitor */
    int  quality;      /* 0 = raw BMP, 1 = basic RLE compression (future) */
    BOOL captureAll;   /* TRUE = full virtual desktop, FALSE = primary only */
} SCREENSHOT_OPTS;

/* ─── Screenshot result ─── */
typedef struct _SCREENSHOT_RESULT {
    unsigned char *data;       /* Heap-allocated BMP file bytes */
    DWORD          dataLen;    /* Size of BMP data */
    int            width;
    int            height;
    int            bpp;        /* Bits per pixel (typically 32) */
    char           errorMsg[128];
} SCREENSHOT_RESULT;

/*
 * Capture a screenshot of the desktop.
 *
 * Returns TRUE on success. result->data is heap-allocated;
 * caller must free with screenshot_free().
 */
BOOL screenshot_capture(const SCREENSHOT_OPTS *opts, SCREENSHOT_RESULT *result);

/*
 * Free screenshot data.
 */
void screenshot_free(SCREENSHOT_RESULT *result);

#endif /* SCREENSHOT_H */
