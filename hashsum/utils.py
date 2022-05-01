from typing import Iterator, Any, Iterable, BinaryIO, TextIO, Union, Callable, Tuple, Optional
from itertools import islice

import os
import sys
import time
import random
import psutil
import hashlib
import zipfile
import tarfile
import threading

YES = 'y yes yea yeah yep yup'.split()


class StoppableThread(threading.Thread):
    """Thread class with a stop() method. The thread itself has to check
    regularly for the stopped condition."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    @property
    def stopped(self):
        return self._stop_event.is_set()


def get_mem_files(log_errors=False) -> Iterator[str]:
    for proc in psutil.process_iter():
        try:
            yield proc.exe()
            yield from map(lambda x: x.path, proc.open_files())
        except psutil.Error as e:
            if log_errors:
                sys.stderr.write(str(e))


def all_files(path: str, subdirs=True) -> Iterator[str]:
    if os.path.isfile(path):
        yield path

    elif subdirs:
        for root, _, files in os.walk(path):
            for file in files:
                if file is not None and root is not None:
                    yield os.path.join(root, file)

    else:
        for file in os.listdir(path):
            file = os.path.join(path, file)
            if file is not None and os.path.isfile(file):
                yield file


def iter_all_files(paths: Iterable[str], subdirs=True) -> Iterator[str]:
    for path in paths:
        yield from all_files(path, subdirs)


def iter_random_files(paths: Iterable[str], count: int, subdirs=True) -> Iterator[Any]:
    files = list(iter_all_files(paths, subdirs=subdirs))
    if count >= len(files):
        return iter(files)

    for _ in range(count):
        file = random.choice(files)
        yield file
        files.remove(file)


def iter_recent_files(paths: Iterable[str], hours: Union[float, int], modified=True, subdirs=True, ignore_errors=True) -> Iterator[Any]:
    now = time.time()
    func = os.path.getmtime if modified else os.path.getatime

    for file in iter_all_files(paths, subdirs=subdirs):
        try:
            if (now - func(file)) / 3600 <= hours:
                yield file
        except os.error as e:
            if not ignore_errors:
                raise e


def all_dirs(directory: str) -> Iterator[Any]:
    return (os.path.join(root, d) for root, dirs, _ in os.walk(directory) for d in dirs if d is not None if
            root is not None)


def file_iter(path: str) -> Iterator[Any]:
    if os.path.isfile(path): return path
    for root, _, files in os.walk(path):
        for file in files:
            yield os.path.join(root, file)


def dir_iter(directory: str) -> Iterator[Any]:
    for root, dirs, _ in os.walk(directory):
        for d in dirs:
            yield os.path.join(root, d)


def traverse(o: Iterable, tree_types=(list, tuple)):
    if isinstance(o, tree_types):
        for value in o:
            for subvalue in traverse(value, tree_types):
                yield subvalue
    else:
        yield o


def hash_from_str(x: str) -> int:
    return int(x, 16)


def hash_from_bytes(x: bytes) -> int:
    return hash_from_str(x.hex())


def hash_from_int(x: int) -> bytes:
    return bytes.fromhex(hex(x))


def hash_to_hex(x: int) -> str:
    return hex(x)[2:]


def get_md5(path: str = None, file_obj: BinaryIO = None, chunksize: int = None) -> int:
    #assert path is not None or file_obj is not None
    hash_md5 = hashlib.md5()

    if path:
        f = open(path, 'rb')
    else:
        f = file_obj

    if chunksize:
        for chunk in iter(lambda: f.read(chunksize), b''):
            hash_md5.update(chunk)
    else:
        hash_md5.update(f.read())

    if path:
        f.close()

    return hash_from_str(hash_md5.hexdigest())


def read_in_chunks(file_obj: Union[TextIO, BinaryIO], chunk_size: int) -> Iterator[Union[bytes, str]]:
    """
    Read a file in chunks generator
    :param file_obj: file object to read from
    :param chunk_size: size of chunks to read
    :return: yields a chunk read from file_obj of size chunk_size
    """
    while True:
        data = file_obj.read(chunk_size)
        if not data:
            break

        yield data


def iter_chunks(chunksize: int, iterable: Iterable) -> Iterator:
    i = iter(iterable)
    piece = list(islice(i, chunksize))
    while piece:
        yield piece
        piece = list(islice(i, chunksize))


def int_to_bytes(num: int) -> bytes:
    """
    Convert an unsigned integer to a bytes object
    :param num: unsigned integer to convert
    :return: bytes object
    """
    return num.to_bytes((num.bit_length() + 7) // 8, 'big')


def bytes_to_int(bytes_obj: bytes) -> int:
    """
    Convert a bytes object to an unsigned integer
    :param bytes_obj: bytes object to convert
    :return: unsigned integer
    """
    return int.from_bytes(bytes_obj, 'big')


def version_to_dbversion(version: int) -> str:
    """
    Convert an integer version to VirusShare database format
    :param version: integer version
    :return: str, VirusShare format version
    """
    v = str(version)
    return '0' * (5 - len(v)) + v


def check_yes(text: str) -> bool:
    return input(f'{text} [y/N] ').lower() in YES


def default_setting(text: str, default: Any) -> str:
    value = input(f'{text} [{default}]: ')
    if not value:
        value = default

    return value


def timesince(start: float) -> float:
    return time.time() - start


def estimate_time(n_total: int, n_done: int, start_time: float) -> float:
    """
    Estimated time remaining in seconds.
    :param n_total: total number of tasks
    :param n_done: number of tasks finished
    :param start_time: time.time() of beginning of tasks
    :return: estimated time remaining in seconds
    """
    try:
        return (n_total - n_done) * timesince(start_time) / n_done
    except ZeroDivisionError:
        return 0.


def iter_archive_files(path: str) -> Iterator[Tuple[str, Optional[Union[zipfile.ZipFile, tarfile.TarFile]]]]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for file in archive.namelist():
                yield file, archive

    elif tarfile.is_tarfile(path):
        with tarfile.TarFile(path) as archive:
            for file in archive.getmembers():
                yield file, archive

    else:
        yield path, None


def archive_to_fileobj(path: str, archive: Union[zipfile.ZipFile, tarfile.TarFile]) -> Tuple[str, Optional[BinaryIO]]:
    if isinstance(archive, zipfile.ZipFile):
        return archive.filename, archive.open(path, 'r')
    elif isinstance(archive, tarfile.TarFile):
        return archive.name, archive.extractfile(path)
    else:
        return path, None


def convert_db(old_filename: str, new_filename: str):
    """Convert the old database format which used text
    to the new format which stores the signatures in binary.
    """
    with open(old_filename, 'r') as f:
        data = []
        for line in f:
            try:
                data.append(bytes.fromhex(line.strip()))
            except ValueError:
                continue

    with open(new_filename, 'wb') as f:
        f.write(b''.join(data))
