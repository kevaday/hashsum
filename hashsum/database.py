from hashsum import DATABASE_FILENAME, VERSION_FILENAME, DATABASE_URL, DATABASE_WORKERS, \
    UPDATE_CHUNKSIZE, CLASSIFIER_FILENAME, BATCH_SIZE, EMPTY_HASH, HASH_LENGTH, TORCH_REQUIRED, \
    NUM_SIGNATURES_1, NUM_FILES_1, NUM_SIGNATURES_2, UPDATE_WORKERS
from hashsum import utils
from hashsum.errors import UpdateNotAvailableError, LoadError, READ_ERRORS
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from multiprocessing import Lock, Queue, Process
from typing import Union, Any, Tuple, Callable, List, BinaryIO
from abc import ABC, abstractmethod, abstractproperty
from functools import partial
from enum import IntEnum

import os
import requests
import atexit
import threading
import pickle

if TORCH_REQUIRED:
    from classifier.utils import load_model, output_to_class, malware_prob, set_device, path_to_tensor, get_device, \
        get_max, TFMS


def _set_load(func):
    def wrapper(self, *args, **kwargs):
        already_set = False
        if self.state == BaseDatabase.STATE_LOADING:
            already_set = True
        else:
            self._set_state(BaseDatabase.STATE_LOADING)
        result = func(self, *args, **kwargs)
        if not already_set:
            self._reset_state()
        return result

    return wrapper


class DatabaseResult(object):
    def __init__(self, path: str, malicious: bool = None, is_archive: bool = False, in_archive: bool = False, details: dict = None, error: str = None):
        self.path = path
        self.malicious = malicious
        self.is_archive = is_archive
        self.in_archive = in_archive
        self.details = details
        self.error = error
        if not details:
            self.details = {}

    def __repr__(self):
        return f"<DatabaseResult path={self.path}, malicious={self.malicious}, is_archive={self.is_archive}, in_archive={self.in_archive}, details={self.details}, error={self.error}>"


class BaseDatabase(ABC):
    _SENTINEL = object()
    _NOT_LOADED = -1

    STATE_IDLE = 0
    STATE_LOADING = 1
    STATE_RUNNING = 2
    STATE_STOPPING = 3

    def __init__(self, updateable=False, thread_safe=False, load=False, scan_side_calc=False, multi_lookup=False,
                 has_version=False, on_load_fn=None, version_path=VERSION_FILENAME, workers=DATABASE_WORKERS):
        self._state = BaseDatabase.STATE_IDLE
        self.__updateable = updateable
        self.__scan_side_calc = scan_side_calc
        self.__multi = multi_lookup
        self.__has_version = has_version
        self.thread_safe = thread_safe
        self.on_load_fn = on_load_fn
        self.version_path = os.path.abspath(version_path)
        self.workers = workers
        self.__version = self._NOT_LOADED
        self.__lookup_q = Queue()
        self.__result_q = None
        self._lookup_pool = None
        self.loaded = False
        if load: self.load()
        atexit.register(self.__del__)

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['_lookup_pool']
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)

    @_set_load
    def __del__(self):
        self.stop_lookup(True)
        self.unload()

    @property
    def updatable(self):
        return self.__updateable

    @property
    def scan_side_calc(self):
        return self.__scan_side_calc

    @property
    def multi_lookup(self):
        return self.__multi

    @property
    def has_version(self):
        return self.__has_version

    @property
    def state(self) -> int:
        return self._state

    @property
    def version(self) -> int:
        return self.__version

    @version.setter
    def version(self, value: int):
        self._write_version(value)
        self.__version = value

    def _set_state(self, state: int) -> None:
        self._state = state

    def _reset_state(self) -> None:
        self._state = BaseDatabase.STATE_IDLE

    @_set_load
    def load(self, *args, **kwargs):
        ...
        if self.has_version:
            self._load_version()
        if self.on_load_fn:
            self.on_load_fn()
        self.loaded = True
    
    def unload(self):
        ...
        self.loaded = False

    @_set_load
    def _load_version(self) -> None:
        if os.path.isfile(self.version_path):
            with open(self.version_path, 'rb') as f:
                self.__version = pickle.load(f)[self.__class__.__name__]
        else:
            self.__version = self._NOT_LOADED

    @_set_load
    def _write_version(self, version: int) -> None:
        version_dict = {}
        if os.path.isfile(self.version_path):
            with open(self.version_path, 'rb') as f:
                version_dict = pickle.load(f)

        version_dict[self.__class__.__name__] = version
        with open(self.version_path, 'wb') as f:
            pickle.dump(version_dict, f)

    @property
    def is_connected(self):
        return self.__result_q is not None

    @property
    def is_lookup_running(self):
        return self._lookup_pool is not None

    def connect(self, result_queue: Queue) -> Queue:
        self.__result_q = result_queue
        return self.__lookup_q

    def disconnect(self):
        if self.is_lookup_running:
            raise RuntimeError('Cannot disconnect database, lookup is running')

        self.__lookup_q = Queue()
        self.__result_q = None
        self._lookup_pool = None

    def start_lookup(self):
        if self.is_lookup_running:
            raise RuntimeError('Lookup is already running')
        elif not self.is_connected:
            raise RuntimeError('Cannot start lookup, not connected to result queue')

        self._lookup_pool = ThreadPoolExecutor(max_workers=self.workers + 1)
        self._lookup_pool.submit(self.__lookup_loop)

    def stop_lookup(self, block=False):
        if not self.is_lookup_running: return
        self.__lookup_q.put(self._SENTINEL)
        self._lookup_pool.shutdown(wait=block)
        self._lookup_pool = None

    def __lookup_loop(self):
        while True:
            item = self.__lookup_q.get()
            if item is self._SENTINEL:
                break
            self._lookup_pool.submit(self.__lookup_result, item)

    def __lookup_result(self, item):
        self.__result_q.put(self.lookup(*item))

    @staticmethod
    def _default_calc(path: str, scan_archive_files: bool, calc_func: Callable[[Union[str, BinaryIO, ]], Any],
                      *calc_args, **calc_kwargs) -> Tuple[Any, DatabaseResult, List[Tuple[Any, DatabaseResult]]]:
        result = None
        is_archive = False
        archive_files = []

        try:
            if scan_archive_files:
                for file, archive in utils.iter_archive_files(path):
                    if archive is None:
                        break

                    is_archive = True
                    _, fileobj = utils.archive_to_fileobj(file, archive)
                    fileobj.seek(0, os.SEEK_END)
                    size = fileobj.tell()
                    fileobj.seek(0, os.SEEK_SET)

                    if size > 0:
                        result = calc_func(file_obj=fileobj, *calc_args, **calc_kwargs)
                        archive_files.append((result, DatabaseResult(file, in_archive=True, details={'size': size})))
                    else:
                        archive_files.append((None, DatabaseResult(file, in_archive=True, error='Empty file')))

            size = os.path.getsize(path)
            if size > 0:
                result = calc_func(path, *calc_args, **calc_kwargs)
            else:
                return (
                    result,
                    DatabaseResult(
                        path, error='Empty file', is_archive=is_archive, details={'archive_files': archive_files}
                    ),
                    archive_files
                )

        except READ_ERRORS as e:
            return (
                result,
                DatabaseResult(
                    path, error=str(e), is_archive=is_archive, details={'archive_files': archive_files}
                ),
                archive_files
            )

        return (
            result,
            DatabaseResult(
                path, is_archive=is_archive, details={'size': size, 'archive_files': archive_files}
            ),
            archive_files
        )

    @staticmethod
    @abstractmethod
    def do_calc(path: str, *args, **kwargs) -> Any:
        pass

    @abstractmethod
    def lookup(self, path: str, *args, **kwargs) -> DatabaseResult:
        pass


class DummyDatabase(BaseDatabase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._set_state(BaseDatabase.STATE_IDLE)

    @staticmethod
    def do_calc(path: str, *args, **kwargs) -> Any:
        return path

    def lookup(self, path: str, *args, **kwargs) -> DatabaseResult:
        return DatabaseResult(path)


class HashDatabase(BaseDatabase, set):
    def __init__(self, path=DATABASE_FILENAME, update_url=DATABASE_URL, load=False,
                 update_workers=UPDATE_WORKERS, update_chunksize=UPDATE_CHUNKSIZE, *args, **kwargs):
        self.path = os.path.abspath(path)
        self.update_url = update_url
        self.update_obj = HashUpdate(self, workers=update_workers, download_chunksize=update_chunksize)
        self.__load_thread = None
        set.__init__(self)
        BaseDatabase.__init__(self, updateable=True, thread_safe=False, scan_side_calc=True, load=load, *args, **kwargs)

    @property
    def signatures(self) -> int:
        return len(self)

    @_set_load
    def load(self, block=True):
        if not os.path.isfile(self.path):
            self._reset_state()
            raise LoadError('The database file could not be found and therefore could not be loaded.')

        self.__load_thread = threading.Thread(target=self.__load, daemon=True)
        self.__load_thread.start()
        if block:
            self.__load_thread.join()

    def __load(self) -> None:
        raw_bytes = open(self.path, 'rb').read()
        for i in range(0, len(raw_bytes), HASH_LENGTH):
            self.add(utils.hash_from_bytes(raw_bytes[i:i + HASH_LENGTH]))
        del raw_bytes

        if EMPTY_HASH in self: self.remove(EMPTY_HASH)
        super().load()
        if self.version == self._NOT_LOADED:
            self._estimate_version()

    def _estimate_version(self) -> None:
        sigs = self.signatures
        version = 0

        while sigs > 0 and version < NUM_FILES_1:
            sigs -= NUM_SIGNATURES_1
            version += 1

        version += sigs // NUM_SIGNATURES_2
        if sigs % NUM_SIGNATURES_2:
            version += 1

        self.version = version
    
    def unload(self):
        self.clear()
        super().unload()

    @staticmethod
    def do_calc(path: str, scan_archive_files=False, file_load_chunksize: int = None) -> Tuple[str, DatabaseResult]:
        md5, result, archive_files = BaseDatabase._default_calc(
            path, scan_archive_files, utils.get_md5, chunksize=file_load_chunksize
        )

        if scan_archive_files:
            for archive_md5, archive_result in archive_files:
                archive_result.details['md5'] = archive_md5
                result.details['archive_files'].append(archive_result)
        result.details['md5'] = md5

        return path, result

    def lookup(self, path: str, _calc_result: DatabaseResult = None, *calc_args, **calc_kwargs) -> DatabaseResult:
        result = _calc_result or self.do_calc(path, *calc_args, **calc_kwargs)

        malicious = False
        if result.is_archive:
            for archive_result in result.details.get('archive_files', []):
                md5 = archive_result.details.get('md5')
                if md5:
                    if md5 in self:
                        malicious = True
                        archive_result.malicious = True
                    archive_result.details['md5'] = utils.hash_to_hex(md5)

        md5 = result.details.get('md5')
        if md5:
            if md5 in self:
                malicious = True
            result.details['md5'] = utils.hash_to_hex(md5)

        result.malicious = malicious
        return result


class NNDatabase(BaseDatabase):
    def __init__(self, path=CLASSIFIER_FILENAME, batch_size=BATCH_SIZE, gpu=True, *args, **kwargs):
        self.path = path
        self.batch_size = batch_size
        self.__gpu = None
        self.learner = None
        self.load_thread = None
        self.data_loader = None
        self.gpu = gpu
        super().__init__(updateable=False, *args, **kwargs)

    @property
    def gpu(self):
        return self.__gpu

    @gpu.setter
    def gpu(self, value):
        self.__gpu = value
        set_device(value)

    @_set_load
    def load(self, block=True):
        self.load_thread = threading.Thread(target=self.__load, daemon=True)
        self.load_thread.start()
        if block: self.load_thread.join()

    def __load(self):
        self.learner = load_model(self.path)
        self.learner.model.train(False)
        super().load()
    
    def unload(self):
        self.learner = None
        self.data_loader = None
        super().unload()

    def do_calc(self, path: str, scan_archive_files: bool = True, *args, **kwargs):
        return path, BaseDatabase._default_calc(
            path, scan_archive_files, path_to_tensor
        )

    def lookup(self, path: str, _inp=None, _result=None, _archive_files=None,
               *calc_args, **calc_kwargs) -> DatabaseResult:
        if not _result:
            _, _inp, _result, _archive_files = self.do_calc(path, *calc_args, **calc_kwargs)

        for archive_inp, archive_result in _archive_files:
            archive_inp = archive_inp.to(get_device())
            output = self.learner.model(archive_inp.unsqueeze(0))
            cls = output_to_class(self.learner, output)[0]
            confidence = get_max(output)[0]
            prob = malware_prob(self.learner, output)[0]

            archive_result.malicious = (cls != 'Legitimate')
            archive_result.details['class'] = cls
            archive_result.details['confidence'] = confidence
            archive_result.details['malware_prob'] = prob

            _result.details['archive_files'].append(archive_result)

        _inp = _inp.to(get_device())
        output = self.learner.model(_inp.unsqueeze(0))
        cls = output_to_class(self.learner, output)[0]
        confidence = get_max(output)[0]
        prob = malware_prob(self.learner, output)[0]
        malicious = (cls != 'Legitimate')

        _result.malicious = malicious
        _result.details['class'] = cls
        _result.details['confidence'] = confidence
        _result.details['malware_prob'] = prob

        return _result

    # def lookups(self, paths: list):
    #    self.data_loader.dataset.update(paths)


'''
class DatabaseWrapper(socket.socket):
    def __init__(self, database: BaseDatabase, port: int = None) -> None:
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.database = database

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        try:
            ip = s.getsockname()[0]
        except:
            ip = ''
        s.close()

        if not port:
            port = random.randint(1000, 65535)
        self.addr = (ip, port)
        self._thread = _StoppableThread(target=self._main, daemon=True)
        atexit.register(self.stop)

    def start(self):
        self.bind(self.addr)
        self.listen(1)
        self._thread.start()

    def stop(self):
        self._thread.stop()
        try:
            self.shutdown(1)
        except socket.error:
            pass

    def running(self):
        return not self._thread.stopped()

    def _main(self):
        conn, _ = self.accept()

        while self.running():
            try:
                data = conn.recv(65535)
                result = bytes([1]) if self.database.lookup(data) else bytes([0])
                conn.sendall(result)
            except socket.error:
                break
'''


class HashUpdate(object):
    STATE_IDLE = 0
    STATE_CHECKING = 1
    STATE_APPLYING = 2
    STATE_STOPPING = 3

    def __init__(self, database: HashDatabase, workers: int = DATABASE_WORKERS,
                 download_chunksize: int = UPDATE_CHUNKSIZE, available=False):
        self.database = database
        self.workers = workers
        self.chunksize = download_chunksize
        self.available = available
        self.version = None
        self.db_path = database.path
        self.update_url = database.update_url
        self.pool = None
        self._thread = None
        self._state = HashUpdate.STATE_IDLE
        self._lock = Lock()

    @property
    def state(self) -> int:
        return self._state

    def _set_state(self, state: int) -> None:
        self._state = state

    def check(self) -> 'HashUpdate':
        self._set_state(HashUpdate.STATE_CHECKING)
        self.available = False
        if self.database.version == self.database._NOT_LOADED:
            return self

        next_version = utils.version_to_dbversion(int(self.database.version) + 1)

        try:
            r = requests.get(self.update_url.format(next_version))
            if r.status_code == 200:
                self.available = True
                self.version = next_version
        except requests.exceptions.RequestException:
            pass

        self._set_state(HashUpdate.STATE_IDLE)

        return self

    def _download(self, version: int, load_into_memory=False, print_download=False) -> bool:
        if self.state is not HashUpdate.STATE_APPLYING:
            return False

        url = self.update_url.format(utils.version_to_dbversion(version))
        if print_download:
            print(f'Downloading {url}')
        try:
            r = requests.get(url, allow_redirects=True)
        except requests.exceptions.RequestException:
            return False

        if r.content:
            if r.status_code != 200:
                return False

            data = []
            for line in r.content.decode().split('\n'):
                try:
                    data.append(bytes.fromhex(line))
                except ValueError:
                    pass

            self._lock.acquire()
            with open(self.database.path, 'ab') as f:
                f.write(b''.join(data))

            if load_into_memory:
                self.database.update(data)
            if version > self.database.version:
                self.database.version = version
                self.version = version

            self._lock.release()
            return True

        return False

    def apply_async(self, *args, **kwargs):
        self._thread = threading.Thread(target=self.apply, args=args, kwargs=kwargs, daemon=True)
        self._thread.start()

    def apply(self, *args, **kwargs) -> None:
        if not self.available:
            raise UpdateNotAvailableError(f'Cannot apply an update when it is not available.'
                                          f' Current version: {self.database.version}')
        self._set_state(HashUpdate.STATE_APPLYING)

        if not self.chunksize:
            self.chunksize = max(self.workers // 2, 1)

        results = []
        with ThreadPoolExecutor(self.workers) as self.pool:
            while all(results) and self.state is HashUpdate.STATE_APPLYING:
                version = int(self.database.version)
                results = self.pool.map(
                    partial(self._download, *args, **kwargs),
                    range(version + 1, version + self.workers * self.chunksize + 1)
                )

        if not self.state == HashUpdate.STATE_STOPPING:
            self.available = False
        self._set_state(HashUpdate.STATE_IDLE)

    def stop(self):
        self._set_state(HashUpdate.STATE_STOPPING)
