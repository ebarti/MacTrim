"""ctypes ABI for directory-only callbacks from the system FTS collector."""
import ctypes as C
from pathlib import Path
import sys

from .safety import SafetyError

ENTER, UPDATE, FINISH, DISCOVER, PUBLISH = range(1, 6)
LINKED, REUSED, COLLAPSED = 1, 2, 4
REASONS = ('', 'Virtual filesystem', 'Redundant APFS Data namespace alias',
           'Verified scanner state accounted separately', 'Cloud placeholder not hydrated',
           'External mount boundary', 'Already accounted directory/firmlink inode',
           'Symlink target not followed', 'Special object not read', 'Already accounted hardlink')


class Record(C.Structure):
    _fields_ = [(key, C.c_uint64) for key in (
        'id', 'parent', 'alias', 'dev', 'ino', 'mode', 'stat_size', 'mtime_ns', 'ctime_ns',
        'logical', 'allocated', 'entries', 'direct_files', 'own_logical', 'own_allocated',
        'modified7', 'modified30', 'created7', 'newest_ns', 'visited', 'denied', 'excluded', 'changed', 'reused')]
    _fields_ += [('reasons', C.c_uint64 * len(REASONS))]
    _fields_ += [(key, C.c_uint32) for key in ('status', 'reason', 'flags', 'depth')]
    _fields_ += [('error', C.c_int32), ('path', C.c_char_p), ('error_path', C.c_char_p)]


Callback = C.CFUNCTYPE(C.c_int, C.c_int, C.POINTER(Record), C.c_void_p)
_library = None


def library():
    global _library
    if _library is None:
        path = (Path(sys._MEIPASS) / 'libmactrim_storage.dylib' if getattr(sys, 'frozen', False) else
                Path(__file__).resolve().parent.parent / 'build' / 'native' / 'libmactrim_storage.dylib')
        if not path.is_file():
            raise SafetyError('Native Storage collector missing; build it with python scripts/build_native.py')
        lib = C.CDLL(str(path))
        lib.mactrim_storage_abi.restype = C.c_uint32
        lib.mactrim_storage_record_size.restype = C.c_uint32
        if lib.mactrim_storage_abi() != 1 or lib.mactrim_storage_record_size() != C.sizeof(Record):
            raise SafetyError('Unsupported native Storage collector ABI')
        lib.mactrim_storage_scan.argtypes = [C.c_char_p, C.POINTER(C.c_char_p), C.c_size_t, C.c_int, Callback, C.c_void_p]
        lib.mactrim_storage_scan.restype = C.c_int
        _library = lib
    return _library


def scan(path, exclusions, lazy, callback):
    import os
    errors = []
    def guarded(kind, pointer, _):
        if errors:
            return 2
        try:
            return callback(kind, pointer.contents) or 0
        except BaseException as exc:
            errors.append(exc)
            return 2
    bridge = Callback(guarded)
    encoded = [os.fsencode(value) for value in exclusions]
    values = (C.c_char_p * len(encoded))(*encoded)
    result = library().mactrim_storage_scan(os.fsencode(path), values, len(encoded), int(lazy), bridge, None)
    if errors:
        raise errors[0]
    if result < 0:
        raise SafetyError('Native Storage traversal failed; previous saved index preserved')
    return result
