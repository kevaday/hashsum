from hashsum import DATABASE_FILENAME, VERSION_FILENAME, DATABASE_URL, LOAD_CHUNKSIZE, DATABASE_WORKERS, \
    UPDATE_CHUNKSIZE, HASH_LINE_SIZE, CLASSIFIER_FILENAME, BATCH_SIZE, EMPTY_HASH, TORCH_REQUIRED
from hashsum import utils
from hashsum.errors import UpdateNotAvailableError, LoadError, READ_ERRORS
from multiprocessing.pool import ThreadPool
from multiprocessing import Lock, Queue
from abc import ABC, abstractmethod, abstractproperty
from functools import partial

import os
import requests
import atexit
import threading

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
    def __init__(self, path: str, malicious: bool = None, details: dict = None, error: str = None):
        self.path = path
        self.malicious = malicious
        self.details = details
        self.error = error
        if not details:
            self.details = {}

    def __repr__(self):
        return f'{self.__class__.__name__}(path={self.path}, malicious={self.malicious}, details={self.details})'


class BaseDatabase(object):
    _NOT_LOADED = -1

    STATE_IDLE = 0
    STATE_LOADING = 1
    STATE_RUNNING = 2
    STATE_STOPPING = 3

    def __init__(self, updateable=False, thread_safe=False, load=False, scan_side_calc=False, multi_lookup=False,
                 on_load_fn=None):
        self._state = BaseDatabase.STATE_IDLE
        self.__updateable = updateable
        self.__scan_side_calc = scan_side_calc
        self.__multi = multi_lookup
        self.thread_safe = thread_safe
        self.on_load_fn = on_load_fn
        self.__q = Queue()
        self.__put_q = None
        self.__t = None
        self.loaded = False
        if load: self.load()
        atexit.register(self.__del__)

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
    def state(self) -> int:
        return self._state

    def _set_state(self, state: int) -> None:
        self._state = state

    def _reset_state(self) -> None:
        self._state = BaseDatabase.STATE_IDLE

    @_set_load
    #@abstractmethod
    def load(self, *args, **kwargs):
        ...
        if self.on_load_fn: self.on_load_fn()
        self.loaded = True
    
    def unload(self):
        ...
        self.loaded = False

    @property
    def is_connected(self):
        return self.__put_q is not None

    @property
    def is_lookup_running(self):
        return self.__t is not None and self.__t.is_alive()

    def connect(self, queue: Queue) -> Queue:
        self.__put_q = queue
        return self.__q

    def start_lookup(self, block=False):
        if self.is_lookup_running: self.stop_lookup(True)
        self.__t = threading.Thread(target=self.__lookup, daemon=True)
        self.__t.start()
        if block:
            self.__t.join()

    def stop_lookup(self, block=False):
        if not self.is_connected: return
        self.__q.put(None)
        if block:
            self.__t.join()

    def __lookup(self):
        while True:
            item = self.__q.get()
            if item is None:
                break
            self.__put_q.put(self.lookup(*item))

    #@abstractmethod
    def do_calc(self, *args, **kwargs):
        if not self.scan_side_calc:
            raise NotImplementedError('This database does not support scan-side calculation.')
        ...

    #@abstractmethod
    def lookup(self, *args, **kwargs) -> DatabaseResult or None:
        if not self.loaded: raise LoadError('The database is not loaded therefore lookup not possible')
        ...


class HashDatabase(BaseDatabase, set):
    def __init__(self, path=DATABASE_FILENAME, version_path=VERSION_FILENAME,
                 update_url=DATABASE_URL, chunksize=LOAD_CHUNKSIZE, load=False, update_workers=DATABASE_WORKERS,
                 update_chunksize=UPDATE_CHUNKSIZE, *args, **kwargs):
        self.path = os.path.abspath(path)
        self.version_path = os.path.abspath(version_path)
        self.update_url = update_url
        self.__chunk = None
        self.chunksize = chunksize
        self.update_obj = HashUpdate(self, workers=update_workers, download_chunksize=update_chunksize)
        self._version = -1
        self.load_thread = None
        set.__init__(self)
        BaseDatabase.__init__(self, updateable=True, thread_safe=False, scan_side_calc=True, load=load, *args, **kwargs)

    @property
    def chunksize(self) -> int:
        return self.__chunk

    @chunksize.setter
    def chunksize(self, value: int):
        if not value:
            self.__chunk = None
        else:
            self.__chunk = int(HASH_LINE_SIZE * round(value / HASH_LINE_SIZE))

    @property
    def version(self) -> int:
        if os.path.isfile(self.version_path):
            self._load_version()
        elif os.path.isfile(self.path):
            self._load_deep_version()
        else:
            self._version = self._NOT_LOADED
        return self._version

    @version.setter
    def version(self, value: int):
        self._set_version(value)
        self._version = value

    @property
    def signatures(self) -> int:
        return len(self)

    @_set_load
    def load(self, block=True):
        if not os.path.isfile(self.path):
            self._reset_state()
            raise LoadError('The database file could not be found and therefore could not be loaded.')

        self.load_thread = threading.Thread(target=self.__load, daemon=True)
        self.load_thread.start()
        if block:
            self.load_thread.join()

    def __load(self) -> None:
        with open(self.path, 'rb') as f:
            for h in utils.read_in_chunks(f, 16):
                self.update([h])
        if EMPTY_HASH in self: self.remove(EMPTY_HASH)
        self._load_version()
        super().load()
    
    def unload(self):
        self.clear()
        super().unload()

    @_set_load
    def _load_version(self) -> None:
        if not os.path.isfile(self.version_path):
            self._load_deep_version()
        else:
            with open(self.version_path) as f:
                self._version = int(f.read())

    @_set_load
    def _load_deep_version(self) -> None:
        for line in self:
            if len(line) == 5:
                new_version = int(line)
                if new_version > self.version:
                    self.version = new_version

    @_set_load
    def _set_version(self, version: int) -> None:
        with open(self.version_path, 'w') as f:
            f.write(str(version))

    def do_calc(self, path: str, *args, **kwargs):
        super().do_calc()
        md5 = None
        size = None
        in_archive = False
        
        try:
            filepath, fileobj = utils.archive_to_fileobj(path, *args, **kwargs)
            in_archive = (fileobj is not None)

            if in_archive:
                path = f'{filepath}->{path}'
                fileobj.seek(0, os.SEEK_END)
                size = fileobj.tell()
                fileobj.seek(0, os.SEEK_SET)
            else:
                size = os.path.getsize(path)
                
            if size > 0:
                if in_archive:
                    md5 = utils.get_md5(file_obj=fileobj, chunksize=self.chunksize)
                else:
                    md5 = utils.get_md5(path, chunksize=self.chunksize)
            else:
                return path, DatabaseResult(path, error='Empty file', details={'in_archive': in_archive})
        except READ_ERRORS as e:
            return path, DatabaseResult(path, error=str(e), details={'in_archive': in_archive})
            
        return path, md5, size, in_archive

    def lookup(self, path: str, _md5: bytes = None, _size: int = None, _in_archive: bool = None, *calc_args, **calc_kwargs) -> DatabaseResult:
        super().lookup()
        result = _md5
        no_calc = (result is None)

        if no_calc:
            result = self.do_calc(path, *calc_args, **calc_kwargs)
        elif isinstance(result, DatabaseResult):
            return _md5

        if no_calc: _, _md5, _size, _in_archive = result
        return DatabaseResult(path, malicious=(_md5 in self),
                              details={
                                  'md5': _md5.hex(),
                                  'size': _size,
                                  'in_archive': _in_archive
                              })


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
    def load(self, block=False):
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

    def do_calc(self, path: str, *args, **kwargs):
        super().do_calc()
        inp = None
        size = None
        in_archive = False
        try:
            filepath, fileobj = utils.archive_to_fileobj(path, *args, **kwargs)
            in_archive = (fileobj is not None)

            if in_archive:
                path = f'{filepath}->{path}'
                fileobj.seek(0, os.SEEK_END)
                size = fileobj.tell()
                fileobj.seek(0, os.SEEK_SET)
            else:
                size = os.path.getsize(path)
                fileobj = path
            
            if size > 0:
                inp = path_to_tensor(fileobj, TFMS)
            else:
                return path, DatabaseResult(path, error='Empty file', details={'in_archive': in_archive})
        except READ_ERRORS as e:
            return path, DatabaseResult(path, error=str(e), details={'in_archive': in_archive})
        
        return path, inp, size, in_archive

    def lookup(self, path: str, _inp=None, _size=None, _in_archive=None, *calc_args, **calc_kwargs) -> DatabaseResult:
        super().lookup()
        result = _inp
        no_calc = False

        if result is None:
            result = self.do_calc(path, *calc_args, **calc_kwargs)
            no_calc = True
        elif isinstance(result, DatabaseResult):
            return _inp
        if no_calc: _, _inp, _size, _in_archive = result

        _inp = _inp.to(get_device())
        output = self.learner.model(_inp.unsqueeze(0))
        cls = output_to_class(self.learner, output)[0]
        confidence = get_max(output)[0]
        prob = malware_prob(self.learner, output)[0]
        malicious = (cls != 'Legitimate')

        return DatabaseResult(path, malicious, details={
            'class': cls,
            'confidence': confidence,
            'malware_prob': prob,
            'size': _size,
            'in_archive': _in_archive
        })

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
        next_version = utils.version_to_dbversion(int(self.database.version) + 1)
        self.available = False

        try:
            r = requests.get(self.update_url.format(next_version))
            if r.status_code == 200:
                self.available = True
        except requests.exceptions.RequestException:
            pass

        self._set_state(HashUpdate.STATE_IDLE)

        return self

    def _download(self, version: int, load_into_memory=False) -> bool:
        if self.state is not HashUpdate.STATE_APPLYING:
            return False

        url = self.update_url.format(utils.version_to_dbversion(version))
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
                    # if 'VirusShare_' in line:
                    #     data.append(line[13:18].encode())

            self._lock.acquire()
            with open(self.database.path, 'ab') as f:
                f.write(b''.join(data))
            if load_into_memory:
                self.database.update(data)
            if version > self.database.version:
                self.database.version = version
            self._lock.release()
            return True

        return False

    def apply_async(self, **kwargs):
        self._thread = threading.Thread(target=self.apply, kwargs=kwargs, daemon=True)
        self._thread.start()

    def apply(self, **kwargs) -> None:
        if not self.available:
            raise UpdateNotAvailableError(f'Cannot apply an update when it is not available.'
                                          f' Current version: {self.database.version}')
        self._set_state(HashUpdate.STATE_APPLYING)

        if not self.chunksize:
            self.chunksize = self.workers // 2

        results = []
        with ThreadPool(self.workers) as self.pool:
            while all(results):
                if self.state is not HashUpdate.STATE_APPLYING:
                    break

                version = int(self.database.version)
                results = self.pool.map(partial(self._download, **kwargs),
                                        range(version + 1, version + self.workers * self.chunksize + 1))

            self.pool.close()
            self.pool.join()

        if not self.state == HashUpdate.STATE_STOPPING:
            self.available = False
        self._set_state(HashUpdate.STATE_IDLE)

    def stop(self):
        self._set_state(HashUpdate.STATE_STOPPING)
