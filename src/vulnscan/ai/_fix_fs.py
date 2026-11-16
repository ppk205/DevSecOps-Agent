"""Handle-confined remediation I/O; no pathname fallback on unsupported hosts.

POSIX walks retained directory descriptors with O_NOFOLLOW. Windows opens each
component with NtCreateFile relative to a retained directory handle, rejects
reparse points, and denies delete sharing while handles are held. Paths are
labels only after acquisition; reads, creates and replacement use the handles.
"""

from __future__ import annotations

import ctypes
import importlib
import os
import re
import stat
import uuid
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path, PureWindowsPath
from typing import Any, Self

_POSIX_DIR_FD = os.open in os.supports_dir_fd and os.mkdir in os.supports_dir_fd


def component(name: str) -> None:
    lower = name.lower()
    if (
        not name
        or name in (".", "..")
        or name.endswith((" ", "."))
        or any(c in name for c in '/\\:<>"|?*')
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
        or lower in (".env", ".secrets", ".git")
        or (lower.startswith(".env.") and lower != ".env.example")
        or re.match(
            r"(?i)^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:[ .]|$)",
            name,
        )
    ):
        raise ValueError("Unsafe, ambiguous or credential path component")


def relative(name: str) -> Path:
    if not name or PureWindowsPath(name).drive or name.startswith("/"):
        raise ValueError("Source path must be relative")
    for part in name.split("/"):
        component(part)
    return Path(name)


def absolute(path: Path) -> Path:
    # Complete lexical preflight precedes opening even the first directory.
    if str(path).startswith(("\\\\?\\", "\\\\.\\")):
        raise ValueError("Windows device namespaces are unsupported")
    result = path.absolute()
    if os.name == "nt" and result.anchor.startswith("\\\\"):
        for part in result.anchor.strip("\\").split("\\"):
            component(part)
    for part in result.parts[1:]:
        component(part)
    return result


def _reparse(info: Any) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("maximum", ctypes.c_uint16),
        ("buffer", ctypes.c_wchar_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("root", ctypes.c_void_p),
        ("name", ctypes.POINTER(_UnicodeString)),
        ("attributes", ctypes.c_uint32),
        ("security", ctypes.c_void_p),
        ("qos", ctypes.c_void_p),
    ]


class _StatusUnion(ctypes.Union):
    _fields_ = [("status", ctypes.c_int32), ("pointer", ctypes.c_void_p)]


class _IoStatus(ctypes.Structure):
    _fields_ = [("status", _StatusUnion), ("information", ctypes.c_size_t)]


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _HandleInfo(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation", _FileTime),
        ("access", _FileTime),
        ("write", _FileTime),
        ("volume", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("links", ctypes.c_uint32),
        ("index_high", ctypes.c_uint32),
        ("index_low", ctypes.c_uint32),
    ]


class _RenameInfo(ctypes.Structure):
    _fields_ = [
        ("replace", ctypes.c_ubyte),
        ("root", ctypes.c_void_p),
        ("length", ctypes.c_uint32),
        ("name", ctypes.c_wchar * 1),
    ]


class _BasicInfo(ctypes.Structure):
    _fields_ = [
        ("creation", ctypes.c_int64),
        ("access", ctypes.c_int64),
        ("write", ctypes.c_int64),
        ("change", ctypes.c_int64),
        ("attributes", ctypes.c_uint32),
    ]


class _Nt:
    """The Windows boundary uses native relative opens and handle renames only."""

    def __init__(self) -> None:
        loader = getattr(ctypes, "WinDLL", None)
        if loader is None:
            raise ValueError("Windows safe handle APIs are unavailable")
        self.runtime: Any = ctypes
        binary, noinherit = getattr(os, "O_BINARY", None), getattr(os, "O_NOINHERIT", None)
        if binary is None or noinherit is None:
            raise ValueError("Windows safe descriptor flags are unavailable")
        self.file_flags: int = binary | noinherit
        self.kernel: Any = loader("kernel32", use_last_error=True)
        self.native: Any = loader("ntdll", use_last_error=True)
        self.kernel.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        self.kernel.CreateFileW.restype = ctypes.c_void_p
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel.GetFileInformationByHandle.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_HandleInfo),
        ]
        self.kernel.SetFileInformationByHandle.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self.native.NtCreateFile.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint32,
            ctypes.POINTER(_ObjectAttributes),
            ctypes.POINTER(_IoStatus),
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self.native.NtCreateFile.restype = ctypes.c_int32
        self.native.NtSetInformationFile.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_IoStatus),
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
        ]
        self.native.NtSetInformationFile.restype = ctypes.c_int32
        self.native.RtlNtStatusToDosError.argtypes = [ctypes.c_int32]
        self.native.RtlNtStatusToDosError.restype = ctypes.c_uint32

    def error(self, status: int | None = None) -> None:
        code = (
            int(self.native.RtlNtStatusToDosError(status))
            if status is not None
            else int(self.runtime.get_last_error())
        )
        if code in (2, 3):
            raise FileNotFoundError(code, "Confined Windows path not found")
        if code in (80, 183):
            raise FileExistsError(code, "Confined Windows path already exists")
        raise OSError(code, "Confined Windows handle operation failed")

    def info(self, handle: int, *, directory: bool | None) -> _HandleInfo:
        info = _HandleInfo()
        if not self.kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            self.error()
        if info.attributes & 0x400 or (
            directory is not None and bool(info.attributes & 0x10) != directory
        ):
            raise ValueError("Windows reparse points and unexpected file types are unsupported")
        if not info.attributes & 0x10 and info.links != 1:
            raise ValueError("Source hardlinks are unsupported")
        return info

    def anchor(self, path: str) -> int:
        handle = self.kernel.CreateFileW(path, 0x1000A0, 3, None, 3, 0x02200000, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            self.error()
        result = int(handle)
        try:
            self.info(result, directory=True)
        except BaseException:
            self.kernel.CloseHandle(result)
            raise
        return result

    def open(self, parent: int, name: str, *, directory: bool | None, create: bool = False) -> int:
        component(name)
        text = ctypes.create_unicode_buffer(name)
        encoded = name.encode("utf-16-le")
        unicode = _UnicodeString(
            len(encoded), len(encoded) + 2, ctypes.cast(text, ctypes.c_wchar_p)
        )
        attrs = _ObjectAttributes(
            ctypes.sizeof(_ObjectAttributes), parent, ctypes.pointer(unicode), 0x1040, None, None
        )
        ios = _IoStatus()
        result = ctypes.c_void_p()
        access = 0x1000A0 if directory else (0x100081 if directory is False else 0x100080)
        if create and not directory:
            access |= 0x10002 | 0x100
        # FILE_OPEN_REPARSE_POINT + synchronous I/O; never follow a component.
        options = 0x200020 | (1 if directory else (0x40 if directory is False else 0))
        status = int(
            self.native.NtCreateFile(
                ctypes.byref(result),
                access,
                ctypes.byref(attrs),
                ctypes.byref(ios),
                None,
                0x80,
                3 if directory or create else 1,
                2 if create else 1,
                options,
                None,
                0,
            )
        )
        if status < 0:
            self.error(status)
        if result.value is None:
            raise ValueError("Windows safe open returned no handle")
        handle = int(result.value)
        try:
            self.info(handle, directory=directory)
        except BaseException:
            self.kernel.CloseHandle(handle)
            raise
        return handle

    def rename(self, handle: int, parent: int, name: str) -> None:
        component(name)
        encoded = name.encode("utf-16-le")
        offset = _RenameInfo.name.offset
        buffer = ctypes.create_string_buffer(max(ctypes.sizeof(_RenameInfo), offset + len(encoded)))
        info = _RenameInfo.from_buffer(buffer)
        info.replace, info.root, info.length = 1, parent, len(encoded)
        ctypes.memmove(ctypes.addressof(buffer) + offset, encoded, len(encoded))
        ios = _IoStatus()
        status = int(
            self.native.NtSetInformationFile(handle, ctypes.byref(ios), buffer, len(buffer), 10)
        )
        if status < 0:
            self.error(status)

    def unlink(self, parent: int, name: str) -> None:
        # Reopen only the entry itself, relative to its locked directory; never a path.
        component(name)
        text = ctypes.create_unicode_buffer(name)
        encoded = name.encode("utf-16-le")
        unicode = _UnicodeString(
            len(encoded), len(encoded) + 2, ctypes.cast(text, ctypes.c_wchar_p)
        )
        attrs = _ObjectAttributes(
            ctypes.sizeof(_ObjectAttributes), parent, ctypes.pointer(unicode), 0x1040, None, None
        )
        ios, handle = _IoStatus(), ctypes.c_void_p()
        status = int(
            self.native.NtCreateFile(
                ctypes.byref(handle),
                0x110080,
                ctypes.byref(attrs),
                ctypes.byref(ios),
                None,
                0x80,
                7,
                1,
                0x200060,
                None,
                0,
            )
        )
        if status < 0:
            self.error(status)
        if handle.value is None:
            raise ValueError("Windows safe delete returned no handle")
        try:
            self.info(int(handle.value), directory=False)
            disposition = ctypes.c_ubyte(1)
            status = int(
                self.native.NtSetInformationFile(
                    handle, ctypes.byref(ios), ctypes.byref(disposition), 1, 13
                )
            )
            if status < 0:
                self.error(status)
        finally:
            self.kernel.CloseHandle(handle)

    def mode(self, handle: int, mode: int) -> None:
        attributes = self.info(handle, directory=False).attributes
        attributes = attributes & ~1 if mode & stat.S_IWRITE else attributes | 1
        info = _BasicInfo(0, 0, 0, 0, attributes or 0x80)
        if not self.kernel.SetFileInformationByHandle(
            handle, 0, ctypes.byref(info), ctypes.sizeof(info)
        ):
            self.error()


class Directory:
    def __init__(
        self, handle: int, path: Path, nt: _Nt | None, parent: Directory | None = None
    ) -> None:
        self.handle, self.path, self.nt, self.parent = handle, path, nt, parent
        self.identity = None if nt else os.fstat(handle)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        if self.nt:
            self.nt.kernel.CloseHandle(self.handle)
        else:
            os.close(self.handle)

    def attached(self) -> None:
        if self.nt:
            self.nt.info(self.handle, directory=True)
        elif self.parent and self.identity:
            self.parent.attached()
            current = os.stat(self.path.name, dir_fd=self.parent.handle, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (self.identity.st_dev, self.identity.st_ino):
                raise ValueError("Validated directory binding changed")

    def child(self, name: str, *, create: bool = False, exclusive: bool = False) -> Directory:
        component(name)
        self.attached()
        if self.nt:
            try:
                handle = self.nt.open(self.handle, name, directory=True, create=create)
            except FileExistsError:
                if exclusive:
                    raise
                handle = self.nt.open(self.handle, name, directory=True)
        else:
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=self.handle)
                except FileExistsError:
                    if exclusive:
                        raise
            handle = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_DIRECTORY") | getattr(os, "O_NOFOLLOW"),  # noqa: B009
                dir_fd=self.handle,
            )
            info = os.fstat(handle)
            if not stat.S_ISDIR(info.st_mode) or _reparse(info):
                os.close(handle)
                raise ValueError("Directory links are unsupported")
        return Directory(handle, self.path / name, self.nt, self)

    @contextmanager
    def descend(self, parts: tuple[str, ...], *, create: bool = False) -> Iterator[Directory]:
        with ExitStack() as stack:
            current = self
            for name in parts:
                current = stack.enter_context(current.child(name, create=create))
            yield current

    def kind(self, name: str) -> str:
        component(name)
        self.attached()
        if self.nt:
            handle = self.nt.open(self.handle, name, directory=None)
            try:
                native_info = self.nt.info(handle, directory=None)
                return "directory" if native_info.attributes & 0x10 else "file"
            finally:
                self.nt.kernel.CloseHandle(handle)
        info = os.stat(name, dir_fd=self.handle, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode) and not _reparse(info):
            return "directory"
        if stat.S_ISREG(info.st_mode) and not _reparse(info):
            return "file"
        raise ValueError("Source links and unexpected types are unsupported")

    def new_directory(self, prefix: str) -> Directory:
        return self.child(prefix + uuid.uuid4().hex, create=True, exclusive=True)

    def file(self, name: str, *, create: bool = False) -> File:
        component(name)
        self.attached()
        if self.nt:
            msvcrt = importlib.import_module("msvcrt")
            handle = self.nt.open(self.handle, name, directory=False, create=create)
            try:
                fd = msvcrt.open_osfhandle(
                    handle, (os.O_RDWR if create else os.O_RDONLY) | self.nt.file_flags
                )
            except BaseException:
                self.nt.kernel.CloseHandle(handle)
                raise
        else:
            flags = (os.O_RDWR | os.O_CREAT | os.O_EXCL) if create else os.O_RDONLY
            fd = os.open(name, flags | getattr(os, "O_NOFOLLOW"), 0o600, dir_fd=self.handle)  # noqa: B009
        result = File(fd, self, name)
        try:
            result.info()
        except BaseException:
            os.close(fd)
            raise
        return result

    def replace(self, temporary: File, name: str) -> None:
        component(name)
        self.attached()
        temporary.info()
        if self.nt:
            msvcrt = importlib.import_module("msvcrt")
            self.nt.rename(msvcrt.get_osfhandle(temporary.fd), self.handle, name)
        else:
            os.replace(temporary.name, name, src_dir_fd=self.handle, dst_dir_fd=self.handle)

    def unlink(self, name: str) -> None:
        component(name)
        try:
            if self.nt:
                self.nt.unlink(self.handle, name)
            else:
                os.unlink(name, dir_fd=self.handle)
        except FileNotFoundError:
            pass


class File:
    def __init__(self, fd: int, parent: Directory, name: str) -> None:
        self.fd, self.parent, self.name = fd, parent, name

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        os.close(self.fd)

    def info(self) -> os.stat_result:
        info = os.fstat(self.fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or _reparse(info):
            raise ValueError("Source must be an opened regular file without links")
        if self.parent.nt:
            msvcrt = importlib.import_module("msvcrt")
            self.parent.nt.info(msvcrt.get_osfhandle(self.fd), directory=False)
        return info

    def current(self) -> None:
        self.parent.attached()
        info = self.info()
        if not self.parent.nt:
            entry = os.stat(self.name, dir_fd=self.parent.handle, follow_symlinks=False)
            if (entry.st_dev, entry.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("Source entry changed while its descriptor was held")

    def read(self, limit: int) -> bytes:
        self.current()
        if self.info().st_size > limit:
            raise ValueError("Source file exceeds 1 MiB")
        os.lseek(self.fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(self.fd, min(65536, limit + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise ValueError("Source file exceeds 1 MiB")
        self.current()
        return b"".join(chunks)

    def write(self, data: bytes) -> None:
        self.current()
        view = memoryview(data)
        while view:
            written = os.write(self.fd, view)
            if written <= 0:
                raise OSError("Confined file write made no progress")
            view = view[written:]
        self.current()

    def mode(self, mode: int) -> None:
        self.current()
        if self.parent.nt:
            msvcrt = importlib.import_module("msvcrt")
            self.parent.nt.mode(msvcrt.get_osfhandle(self.fd), mode)
        else:
            getattr(os, "fchmod")(self.fd, mode)  # noqa: B009


@contextmanager
def directory(path: Path, *, create: bool = False) -> Iterator[Directory]:
    path = absolute(path)
    nt = _Nt() if os.name == "nt" else None
    if nt is None and (
        not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY") or not _POSIX_DIR_FD
    ):
        raise ValueError("Safe directory descriptor operations are unavailable")
    anchor = (
        nt.anchor(path.anchor)
        if nt
        else os.open(
            path.anchor,
            os.O_RDONLY | getattr(os, "O_DIRECTORY") | getattr(os, "O_NOFOLLOW"),  # noqa: B009
        )
    )
    with ExitStack() as stack:
        current = stack.enter_context(Directory(anchor, Path(path.anchor), nt))
        for part in path.parts[1:]:
            current = stack.enter_context(current.child(part, create=create))
        yield current
