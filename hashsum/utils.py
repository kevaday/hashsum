from typing import Iterator, Any, Iterable

import os
import time
import random
import hashlib
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


def all_files(path: str, subdirs=True) -> Iterator[Any]:
    if os.path.isfile(path): return path
    if subdirs:
        return (os.path.join(root, f) for root, _, files in os.walk(path)
                for f in files if f is not None if root is not None)
    else:
        return (os.path.join(path, file) for file in os.listdir(path) if os.path.isfile(os.path.join(path, file)))


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


def random_file(files: list):
    return random.choice(files)


def random_files(path: str, count: int, subdirs=True) -> Iterator[Any]:
    files = list(all_files(path, subdirs=subdirs))
    if count >= len(files):
        return files

    for _ in range(count):
        file = random_file(files)
        yield file
        files.remove(file)


def recent_modified_files(path: str, hours: float or int, subdirs=True, ignore_errors=True) -> Iterator[Any]:
    now = time.time()
    for file in all_files(path, subdirs=subdirs):
        try:
            if (now - os.path.getmtime(file)) / 3600 <= hours:
                yield file
        except os.error as e:
            if not ignore_errors:
                raise e


def traverse(o: Iterable, tree_types=(list, tuple)):
    if isinstance(o, tree_types):
        for value in o:
            for subvalue in traverse(value, tree_types):
                yield subvalue
    else:
        yield o


def get_md5(path: str = None, file_obj=None, chunksize=None) -> bytes:
    assert path is not None or file_obj is not None
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

    return hash_md5.digest()


def read_in_chunks(file_obj, chunk_size):
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


def version_to_dbversion(version: int) -> str:
    """
    Convert an integer version to VirusShare database format
    :param version: integer version
    :return: str, VirusShare format version
    """
    zeros = 5 - len(str(version))
    zeros = '0' * zeros
    zeros += str(version)

    return zeros


def check_yes(text: str) -> bool:
    return input(text).lower() in YES


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
        return (n_total - n_done) / (n_done / timesince(start_time))
    except ZeroDivisionError:
        return 0.


def archive_to_fileobj(path: str, zipfile=None, tarfile=None):
    if zipfile:
        return zipfile.filename, zipfile.open(path, 'r')
    elif tarfile:
        return tarfile.name, tarfile.extractfile(path).fileobj
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
