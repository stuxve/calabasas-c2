import sys as _sys

# On Windows, enable ANSI/VT100 escape sequence processing on the stderr
# console handle.  Rich Console writes to stderr (to avoid prompt_toolkit's
# patch_stdout corruption), but Windows only enables VT processing on stdout
# by default — stderr gets the ESC byte displayed as '?' without this.
if _sys.platform == "win32":
    try:
        import ctypes as _ctypes
        _kernel32 = _ctypes.windll.kernel32
        _STD_ERROR_HANDLE = -12
        _ENABLE_VTP = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        _h = _kernel32.GetStdHandle(_STD_ERROR_HANDLE)
        _mode = _ctypes.c_ulong()
        _kernel32.GetConsoleMode(_h, _ctypes.byref(_mode))
        _kernel32.SetConsoleMode(_h, _mode.value | _ENABLE_VTP)
        del _kernel32, _h, _mode, _ctypes
    except Exception:
        pass

del _sys

from .shell import OperatorShell

__all__ = ["OperatorShell"]
