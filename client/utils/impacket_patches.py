"""
Runtime monkey-patches for impacket bugs.

Called at operator startup — patches are applied in-memory,
no impacket source files are modified.
"""
import logging
from struct import unpack

log = logging.getLogger("caraxes.patches")

_applied = False


def apply_patches():
    """Apply all impacket monkey-patches. Safe to call multiple times."""
    global _applied
    if _applied:
        return
    _applied = True

    _patch_ese_getTag()


def _patch_ese_getTag():
    """Fix ESENT_PAGE.getTag crash on large-page (>8KB) ESE databases.

    Bug: getTag() accesses tmpData[1] unconditionally for pages with
    FileFormatRevision >= 17 and PageSize > 8192. On dirty-shutdown
    databases (e.g. raw-copied NTDS.dit from Server 2025 with 32KB pages),
    some tags have 0 or 1 bytes of data, causing IndexError.
    """
    try:
        import impacket.ese as ese
    except ImportError:
        log.debug("impacket not installed — skipping ESE patch")
        return

    def _patched_getTag(self, tagNum):
        if self.tagCount <= tagNum:
            raise Exception('Trying to grab an unknown tag 0x%x' % tagNum)

        tags = self.data[-4 * self.tagCount:]
        baseOffset = len(self.record)
        for i in range(tagNum):
            tags = tags[:-4]
        tag = tags[-4:]

        if (self._ESENT_PAGE__DBHeader['Version'] == 0x620
                and self._ESENT_PAGE__DBHeader['FileFormatRevision'] >= 17
                and self._ESENT_PAGE__DBHeader['PageSize'] > 8192):
            valueSize = unpack('<H', tag[:2])[0] & 0x7fff
            valueOffset = unpack('<H', tag[2:])[0] & 0x7fff
            tmpData = bytearray(
                self.data[baseOffset + valueOffset:][:valueSize])
            if len(tmpData) >= 2:
                pageFlags = tmpData[1] >> 5
                tmpData[1] = tmpData[1:2][0] & 0x1f
            else:
                pageFlags = 0
            tagData = bytes(tmpData)
        else:
            valueSize = unpack('<H', tag[:2])[0] & 0x1fff
            pageFlags = (unpack('<H', tag[2:])[0] & 0xe000) >> 13
            valueOffset = unpack('<H', tag[2:])[0] & 0x1fff
            tagData = self.data[baseOffset + valueOffset:][:valueSize]

        return pageFlags, tagData

    ese.ESENT_PAGE.getTag = _patched_getTag
    log.info("Patched impacket.ese.ESENT_PAGE.getTag (32KB page fix)")
