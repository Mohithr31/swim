"""Read-only endpoint acquisition primitives for browser forensics.

Linux uses the kernel syscall ABI through libc's syscall(2) entry point for
openat/read/close/getdents64/lseek. This is deliberately limited to read-only
acquisition of browser evidence. Parsing is performed separately by the
browser-forensics collector.

This module is not an EDR/AV bypass mechanism; kernel auditing and security
controls can still observe these operations.
"""
from __future__ import annotations

import ctypes
import errno
import os
import struct
import tempfile
from pathlib import Path
from typing import Iterator, Optional, Tuple

# Linux x86-64 syscall numbers used by runtime/jocky_syscall_linux.h.
SYS_READ = 0
SYS_CLOSE = 3
SYS_LSEEK = 8
SYS_OPENAT = 257
SYS_GETDENTS64 = 217
AT_FDCWD = -100
O_RDONLY = 0
O_DIRECTORY = 0o200000
SEEK_SET = 0
SEEK_END = 2

_libc = None
if os.name == "posix" and hasattr(os, "uname") and os.uname().sysname == "Linux":
    _libc = ctypes.CDLL(None, use_errno=True)
    _libc.syscall.restype = ctypes.c_long


def _windows_read_file(path: str, max_bytes: Optional[int] = None) -> bytes:
    """Read a file using Windows kernel32 read-only handles."""
    if os.name != "nt":
        raise OSError(errno.ENOSYS, "Windows native acquisition unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    CreateFileW.restype = ctypes.c_void_p
    ReadFile = kernel32.ReadFile
    ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    ReadFile.restype = ctypes.c_int
    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [ctypes.c_void_p]
    CloseHandle.restype = ctypes.c_int
    handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if not handle or handle == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error() or 5
        raise OSError(err, f"CreateFileW failed for {path}")
    chunks = []
    total = 0
    try:
        while True:
            want = 1024 * 1024
            if max_bytes is not None:
                remaining = max_bytes - total
                if remaining <= 0:
                    break
                want = min(want, remaining)
            buf = ctypes.create_string_buffer(want)
            got = ctypes.c_uint32(0)
            if not ReadFile(handle, buf, want, ctypes.byref(got), None):
                err = ctypes.get_last_error() or 5
                raise OSError(err, f"ReadFile failed for {path}")
            if got.value == 0:
                break
            chunks.append(buf.raw[:got.value])
            total += got.value
        return b"".join(chunks)
    finally:
        CloseHandle(handle)


def _windows_file_size(path: str) -> Optional[int]:
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    CreateFileW.restype = ctypes.c_void_p
    GetFileSizeEx = kernel32.GetFileSizeEx
    GetFileSizeEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_longlong)]
    GetFileSizeEx.restype = ctypes.c_int
    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [ctypes.c_void_p]
    CloseHandle.restype = ctypes.c_int
    handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None, OPEN_EXISTING, 0, None)
    if not handle or handle == INVALID_HANDLE_VALUE:
        return None
    try:
        size = ctypes.c_longlong(0)
        return int(size.value) if GetFileSizeEx(handle, ctypes.byref(size)) else None
    finally:
        CloseHandle(handle)


def _linux_syscall(nr: int, *args: object) -> int:
    if _libc is None:
        raise OSError(errno.ENOSYS, "Linux syscall acquisition unavailable")
    ctypes.set_errno(0)
    result = int(_libc.syscall(ctypes.c_long(nr), *args))
    if result < 0:
        err = ctypes.get_errno() or errno.EIO
        raise OSError(err, os.strerror(err))
    return result


def read_file(path: str, max_bytes: Optional[int] = None) -> bytes:
    """Read a regular file using read-only Linux syscalls when available."""
    if os.name == "nt":
        return _windows_read_file(path, max_bytes=max_bytes)
    if _libc is None:
        with open(path, "rb") as fh:
            return fh.read() if max_bytes is None else fh.read(max_bytes)

    encoded = os.fsencode(path)
    fd = _linux_syscall(SYS_OPENAT, ctypes.c_int(AT_FDCWD), ctypes.c_char_p(encoded), ctypes.c_int(O_RDONLY), ctypes.c_int(0))
    chunks = []
    total = 0
    try:
        while True:
            want = 1024 * 1024
            if max_bytes is not None:
                remaining = max_bytes - total
                if remaining <= 0:
                    break
                want = min(want, remaining)
            buf = ctypes.create_string_buffer(want)
            n = _linux_syscall(SYS_READ, ctypes.c_int(fd), ctypes.byref(buf), ctypes.c_size_t(want))
            if n == 0:
                break
            chunks.append(buf.raw[:n])
            total += n
            if max_bytes is not None and total >= max_bytes:
                break
        return b"".join(chunks)
    finally:
        try:
            _linux_syscall(SYS_CLOSE, ctypes.c_int(fd))
        except OSError:
            pass


def copy_to_temp(path: str, suffix: str = ".sqlite") -> Optional[str]:
    """Acquire a read-only source into a temporary parser copy.

    SQLite browser databases can have uncheckpointed records in ``-wal`` and
    ``-shm`` sidecars.  The source files are acquired through the syscall/native
    read-only layer and copied into the same temporary directory so SQLite can
    reconstruct the current consistent read view.  No source file is opened for
    writing.
    """
    tmp_dir = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="jocky-browser-")
        main_name = os.path.basename(path)
        tmp_main = os.path.join(tmp_dir, main_name)
        with open(tmp_main, "wb") as out:
            out.write(read_file(path))
        # Preserve SQLite WAL/SHM state when present. These are read-only source
        # acquisitions; they are never created or modified on the endpoint.
        for sidecar in (path + "-wal", path + "-shm"):
            if path_exists(sidecar):
                try:
                    with open(os.path.join(tmp_dir, os.path.basename(sidecar)), "wb") as out:
                        out.write(read_file(sidecar))
                except Exception:
                    pass
        return tmp_main
    except Exception:
        if tmp_dir:
            shutil = __import__("shutil")
            shutil.rmtree(tmp_dir, ignore_errors=True)
        return None


def file_bytes(path: str, max_bytes: Optional[int] = None) -> bytes:
    return read_file(path, max_bytes=max_bytes)


def file_size(path: str) -> Optional[int]:
    if os.name == "nt":
        return _windows_file_size(path)
    if _libc is None:
        try:
            return os.path.getsize(path)
        except OSError:
            return None
    try:
        encoded = os.fsencode(path)
        fd = _linux_syscall(SYS_OPENAT, ctypes.c_int(AT_FDCWD), ctypes.c_char_p(encoded), ctypes.c_int(O_RDONLY), ctypes.c_int(0))
        try:
            end = _linux_syscall(SYS_LSEEK, ctypes.c_int(fd), ctypes.c_long(0), ctypes.c_int(SEEK_END))
            return int(end)
        finally:
            try:
                _linux_syscall(SYS_CLOSE, ctypes.c_int(fd))
            except OSError:
                pass
    except OSError:
        return None


def list_dir(path: str) -> Iterator[Tuple[str, int]]:
    """Yield (name, d_type) using getdents64 on Linux."""
    if _libc is None:
        for entry in os.scandir(path):
            yield entry.name, getattr(entry, "_d_type", 0)
        return

    encoded = os.fsencode(path)
    fd = _linux_syscall(SYS_OPENAT, ctypes.c_int(AT_FDCWD), ctypes.c_char_p(encoded), ctypes.c_int(O_RDONLY | O_DIRECTORY), ctypes.c_int(0))
    try:
        bufsize = 64 * 1024
        while True:
            buf = ctypes.create_string_buffer(bufsize)
            nread = _linux_syscall(SYS_GETDENTS64, ctypes.c_int(fd), ctypes.byref(buf), ctypes.c_uint(bufsize))
            if nread == 0:
                break
            offset = 0
            raw = buf.raw
            while offset < nread:
                # linux_dirent64: ino(8), off(8), reclen(2), type(1), name[]
                if offset + 19 > nread:
                    break
                _, _, reclen, dtype = struct.unpack_from("=QQHB", raw, offset)
                if reclen <= 0 or offset + reclen > nread:
                    break
                name_raw = raw[offset + 19: offset + reclen]
                name = name_raw.split(b"\0", 1)[0].decode("utf-8", errors="surrogateescape")
                if name not in (".", ".."):
                    yield name, int(dtype)
                offset += reclen
    finally:
        try:
            _linux_syscall(SYS_CLOSE, ctypes.c_int(fd))
        except OSError:
            pass


def path_exists(path: str) -> bool:
    if _libc is not None:
        parent = os.path.dirname(path) or "."
        name = os.path.basename(path)
        try:
            return any(n == name for n, _ in list_dir(parent))
        except OSError:
            return False
    return os.path.exists(path)
