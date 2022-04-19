import atexit
from collections import OrderedDict
from datetime import datetime, date

from hashsum import utils, REPORT_FILENAME, REPORT_TITLE, SCAN_PATH_WILDCARD
from hashsum import SCAN_WORKERS, FILE_CHUNKSIZE, LOAD_CHUNKSIZE, IS_WINDOWS, SYSTEM_ROOT, TORCH_REQUIRED
from hashsum.database import HashDatabase, BaseDatabase, DatabaseResult, NNDatabase
from hashsum.errors import ScanError, READ_ERRORS

from multiprocessing import Pool
from multiprocessing import Lock, Queue
from threading import Thread

from functools import partial
from typing import Iterator, Any, List, Iterable, Callable, Union
from collections.abc import Generator

import os
import time
import zipfile
import tarfile
import psutil
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

_DISPLAY = False
_DAY = 24
_FIVE_DAYS = 5 * _DAY

if IS_WINDOWS:
    WINDOWS = os.path.join(SYSTEM_ROOT, 'Windows')
    PROGRAM_FILES = os.environ['ProgramFiles']
    PROGRAM_FILES_86 = os.environ['ProgramFiles(x86)']


def _set_scan(func):
    def wrapper(self, *args, **kwargs):
        already_set = False
        if self.state == BaseScanner.STATE_SCANNING:
            already_set = True
        else:
            self._set_state(BaseScanner.STATE_SCANNING)
        result = func(self, *args, **kwargs)
        if not already_set:
            self._reset_state()
        return result

    return wrapper


def _get_paths(query_path) -> Iterator[str]:
    return iter(query_path.load())


class _ScanQueryPath(str):
    def __new__(cls, path: str, load_func: Callable, *load_args, **load_kwargs):
        obj = str.__new__(cls, path)
        obj.load_func = load_func
        obj.load_args = load_args
        obj.load_kwargs = load_kwargs
        return obj

    def load(self) -> Iterator[str]:
        if not self.load_func: return []
        return iter(self.load_func(str(self), *self.load_args, **self.load_kwargs))


class ScanQuery(list):
    def __init__(self, paths: str or 'ScanQuery' = None, load_func: Callable = None, memory=False, print_errors=False,
                 load_while_scanning=True, pool_workers=SCAN_WORKERS, **load_kwargs):
        if not paths: paths = []
        if not load_func: load_func = utils.all_files

        if (paths or load_func) and memory and print_errors:
            raise UserWarning('Paths will be extended with memory files as argument memory=True.')
        elif not paths and not load_func and not memory:
            raise ValueError('Either a path, list of paths, or memory=True should be provided as arguments.')

        paths = list(utils.traverse(paths, tree_types=(ScanQuery, tuple, list)))
        all_paths = self.__to_query_paths(paths, load_func, **load_kwargs)
        all_paths.extend(list(filter(lambda x: isinstance(x, ScanQuery), paths)))
        list.__init__(self, all_paths)
        self.memory = memory
        self.load_while_scanning = load_while_scanning
        self.pool_workers = pool_workers
        self.print_errors = print_errors

    @staticmethod
    def __to_query_paths(paths: Iterable[Any], load_func: Callable = None,
                         *load_args, **load_kwargs) -> List[_ScanQueryPath]:
        temp = []
        for path in paths:
            if isinstance(path, str) and not isinstance(path, _ScanQueryPath):
                p = _ScanQueryPath(path, load_func, *load_args, **load_kwargs)
            else:
                p = path
            temp.append(p)

        return temp

    def load(self) -> Iterator[str] or List[str]:
        if self.load_while_scanning:
            with Pool(self.pool_workers) as pool:
                for paths in pool.imap_unordered(_get_paths, self):
                    for path in paths: yield path

            if self.memory:
                for path in get_mem_files(display_error=self.print_errors): yield path

        else:
            paths = []
            for path in self: paths.extend(_get_paths(path))
            if self.memory: paths.extend([path for path in get_mem_files(display_error=self.print_errors)])

            return paths


def recent_query(path, *args, **kwargs):
    return ScanQuery(path, load_func=utils.recent_modified_files, *args, **kwargs)


def random_query(path, *args, **kwargs):
    return ScanQuery(path, load_func=utils.random_files, *args, **kwargs)


class BaseScanner(object):
    STATE_IDLE = 0
    STATE_LOAD_PATHS = 1
    STATE_SCANNING = 2
    STATE_STOPPING = 3

    def __init__(self, database: BaseDatabase) -> None:
        self._state = self.STATE_IDLE
        self.database = database
        self._lock = Lock()
        self.__q = Queue()
        self.__put_q = None
        self.__t = None
        self.infected = []
        self.files = []
        self.all_files = []
        self.not_scanned = []
        self.results = []
        self.__query = None
        self.__scan_load = False
        self.connect(database)

    def reset_vars(self):
        self.infected = []
        self.files = []
        self.all_files = []
        self.not_scanned = []
        self.results = []

    @property
    def is_connected(self):
        return self.__put_q is not None

    def connect(self, database: BaseDatabase) -> None:
        self.__put_q = database.connect(self.__q)
        database.start_lookup()
        atexit.register(database.stop_lookup, block=True)

    @property
    def state(self) -> int:
        return self._state

    def _set_state(self, state: int) -> None:
        self._state = state

    def _reset_state(self):
        self._state = self.STATE_IDLE

    def __check_connected(self):
        if not self.is_connected:
            raise ValueError('The scanner is not connected to a database, submission is not available.')

    def _submit(self, path):
        self.__check_connected()
        self.__put_q.put(path)

    def _get_result(self, block=True) -> DatabaseResult:
        self.__check_connected()
        return self.__q.get(block)


class Scanner(BaseScanner):
    def __init__(self, database: BaseDatabase, workers: int = SCAN_WORKERS, file_chunksize: int = FILE_CHUNKSIZE,
                 load_chunksize: int = LOAD_CHUNKSIZE, scan_archives=True, print_errors=False):
        BaseScanner.__init__(self, database)
        self.workers = workers
        self.file_chunksize = file_chunksize
        self.load_chunksize = load_chunksize
        self.scan_archives = scan_archives
        self.print_errors = print_errors
        self._start_time = None
        self.elapsed_time = 0
        self.__scan_generator = None

    def __scan_archive(self, path: str, *args, **kwargs) -> List:
        results = []
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                for file in archive.namelist():
                    results.append(self.__scan_path(path=file, _is_archive=True, zipfile=archive, *args, **kwargs))

        elif tarfile.is_tarfile(path):
            with tarfile.TarFile(path) as archive:
                for file in archive.getmembers():
                    results.append(self.__scan_path(path=file, _is_archive=True, tarfile=archive, *args, **kwargs))

        return results

    def __scan_path(self, thread_safe: bool, scan_calc: bool, multi_lookup: bool, path,
                    _is_archive=False, *calc_args, **calc_kwargs) -> List[Union[DatabaseResult, None]]:
        results = []
        result = None
        if self.state != self.STATE_SCANNING: return results

        if not _is_archive and not os.path.isfile(path):
            self.not_scanned.append(path)
            if self.print_errors: print(f'The file {path} does not exist.')
            return results

        try:
            if not _is_archive and self.scan_archives:
                results = self.__scan_archive(path, thread_safe, scan_calc, multi_lookup)

            if scan_calc:
                item = self.database.do_calc(path, *calc_args, **calc_kwargs)
            else:
                item = path
            if thread_safe:
                result = self.database.lookup(*item, *calc_args, **calc_kwargs)
            else:
                self._submit(item)
                result = self._get_result()
        except READ_ERRORS as e:
            self.not_scanned.append(path)
            if self.print_errors: print(f'Failed to read file {path}: {e}')
            return results

        if result is not None:
            results.append(result)
            if result.error: self.not_scanned.append(path)
        else:
            self.not_scanned.append(path)
        results = list(utils.traverse(list(filter(lambda x: x is not None, results))))
        if not _is_archive:
            self.results.extend(results)
            self.files.append(path)
            self.infected.extend(list(filter(lambda x: x.malicious, results)))

        return results

    @_set_scan
    def __iter_results(self) -> Iterator[DatabaseResult or None]:
        broke = False
        with Pool(self.workers) as pool:
            for results in pool.imap_unordered(partial(self.__scan_path, self.database.thread_safe,
                                                       self.database.scan_side_calc, self.database.multi_lookup),
                                               self.__scan_generator(), chunksize=self.file_chunksize):
                for result in results:
                    if self.state == self.STATE_STOPPING:
                        broke = True
                        break
                    yield result

                if broke: break

            pool.close()
            pool.join()

        self.__t = None
        self.elapsed_time = utils.timesince(self._start_time)

    def __scan(self) -> None:
        for _ in self.__iter_results(): pass
        self._reset_state()

    def __scan_iter(self) -> Iterator[DatabaseResult or None]:
        for result in self.__iter_results():
            if result:
                yield result
        self._reset_state()

    def __query_generator(self, query: ScanQuery = None) -> Iterator[str]:
        if query is not None:
            for path in query.load():
                self.all_files.append(path)
                yield path
        else:
            return iter(self.all_files)

    def __start_scan(self, query: ScanQuery):
        self._set_state(self.STATE_SCANNING)
        self.reset_vars()
        if query is None: raise ValueError('Empty Scan Query provided')
        import pdb; pdb.set_trace()
        self.__scan_load = query.load_while_scanning
        if not self.__scan_load:
            self._set_state(self.STATE_LOAD_PATHS)
            self.all_files = list(query.load())
            if not self.all_files:
                return False

            self.__scan_generator = self.__query_generator

            if not self.file_chunksize:
                self.file_chunksize = len(self.all_files) // self.workers
        else:
            self.file_chunksize = 1
            self.__scan_generator = lambda: self.__query_generator(query)

        self._set_state(self.STATE_SCANNING)
        self._start_time = time.time()
        return True

    @staticmethod
    def __get_query(query: ScanQuery = None, *args, **kwargs):
        if not args and query is None:
            raise ValueError('Either scan query args or a Scan Query object must be provided as arguments')

        if query is None:
            query = ScanQuery(*args, **kwargs)
        elif isinstance(query, str):
            query = ScanQuery(query, *args, **kwargs)

        return query

    def _scan(self, query: ScanQuery):
        if self.__start_scan(query):
            self.__scan()

    def scan(self, query: ScanQuery = None, *args, **kwargs) -> Iterator[Union[DatabaseResult, None]]:
        query = self.__get_query(query, *args, **kwargs)
        if self.__start_scan(query):
            return iter(self.__scan_iter())

    def scan_async(self, query: ScanQuery = None, *args, **kwargs):
        query = self.__get_query(query, *args, **kwargs)
        self.__t = Thread(target=self._scan, args=(query,), daemon=True)
        self.__t.start()

    def stop_scan(self, block=True):
        self._set_state(self.STATE_STOPPING)
        if block and self.__t is not None: self.__t.join()

    def generate_report(self, report_file: str = None, verbose: bool = False):
        if not report_file:
            report_file = f'{date.today()}-{REPORT_FILENAME}'

        with open(report_file, 'w') as f:
            f.write(f'{REPORT_TITLE}: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}\n\n')
            f.write(f"Scanned files: {len(list(filter(lambda x: not x.details.get('in_archive'), self.results)))}\n\n")
            f.write(f'Total items scanned (ex. in archive): {len(self.results)}\n\n')
            f.write(f'Total scan time: {self.elapsed_time}\n\n')
            f.write(f'Files not scanned: {len(self.not_scanned)}\n\n')
            if verbose: f.write('Not scanned files:\n' + '\n'.join(self.not_scanned) + '\n\n')
            if self.infected: f.write(f'Suspicious files ({len(self.infected)} found):\n' +
                                      '\n'.join(self.infected) + '\n\n')
            else: f.write('No suspicious files found.')
            if verbose:
                f.write('\n\nScan parameters:\n')
                f.write(f'\tscan workers: {self.workers}\n')
                f.write(f'\tfile chunksize (files per worker thread): {self.file_chunksize}\n')
                f.write(f'\tscan archives: {self.scan_archives}\n')

                f.write(f'\tdatabase:\n')
                f.write(f'\t\ttype: {self.database.__class__.__name__}')
                if hasattr(self.database, 'version'): f.write(f'\t\tversion: {self.database.version}\n')
                if hasattr(self.database, 'signatures'): f.write(f'\t\tsignatures: {self.database.signatures}\n')
                if hasattr(self.database, 'chunksize'): f.write(f'\t\tload chunksize: {self.database.chunksize}\n')
                f.write(f'\t\tscan side calc: {self.database.scan_side_calc}\n')
                f.write(f'\t\tmulti lookup: {self.database.multi_lookup}\n')
                f.write(f'\t\tscan side calc: {self.database.scan_side_calc}\n')

        return report_file


def get_mem_files(display_error=False) -> Iterator[str]:
    for proc in psutil.process_iter():
        try:
            yield proc.exe()
            for path in map(lambda x: x.path, proc.open_files()): yield path
        except psutil.Error as e:
            if display_error:
                print(e)
            else:
                continue


def normal_scan(path: str) -> ScanQuery:
    return ScanQuery(path, load_func=utils.all_files, subdirs=True, memory=False, load_while_scanning=False)


def memory_scan() -> ScanQuery:
    return ScanQuery(memory=True)


def quick_scan() -> ScanQuery:
    if IS_WINDOWS:
        return ScanQuery(
            [SYSTEM_ROOT,
             WINDOWS,
             recent_query(WINDOWS, hours=_FIVE_DAYS, subdirs=True),
             recent_query(PROGRAM_FILES, hours=_DAY, subdirs=True),
             recent_query(PROGRAM_FILES_86, hours=_DAY, subdirs=True)],
            load_func=utils.all_files,
            subdirs=False,
            memory=True
        )
    else:
        five_days = lambda path: recent_query(os.path.join(SYSTEM_ROOT, path), hours=_FIVE_DAYS, subdirs=True)
        return ScanQuery(
            [os.path.join(SYSTEM_ROOT, 'bin'),
             five_days('bin'),
             five_days('usr'),
             five_days('home')],
            load_func=utils.all_files,
            subdirs=False,
            memory=True
        )


def system_scan() -> ScanQuery:
    if IS_WINDOWS:
        return ScanQuery(
            [SYSTEM_ROOT,
             WINDOWS,
             recent_query(SYSTEM_ROOT, hours=_FIVE_DAYS, subdirs=True)],
            load_func=utils.all_files,
            subdirs=False,
            memory=True
        )
    else:
        return ScanQuery(
            [os.path.join(SYSTEM_ROOT, 'bin'),
             os.path.join(SYSTEM_ROOT, 'sbin'),
             recent_query(SYSTEM_ROOT, hours=_FIVE_DAYS, subdirs=True)],
            load_func=utils.all_files,
            subdirs=False,
            memory=True
        )


SCAN_TYPES = OrderedDict({
    'System Scan': (system_scan,),
    'Quick Scan': (quick_scan,),
    'Memory Scan': (memory_scan,),
    'Recently Modified Files Scan': (recent_query, SCAN_PATH_WILDCARD, 'hours last modified'),
    'Random Files Scan': (random_query, SCAN_PATH_WILDCARD, 'number of files')
})


def _get_args(db_types: List[str], scan_types: List[str]):
    from hashsum import DATABASE_WORKERS, UPDATE_CHUNKSIZE
    import argparse

    parser = argparse.ArgumentParser(argparse.ArgumentDefaultsHelpFormatter, description='Command line HashSum '
                                                                                         'interface.')
    parser.add_argument('--display-text', '-d', action='store_true', default=False, help='display scan result '
                                                                                         'for each individual '
                                                                                         'item')
    parser.add_argument('--database', '-db', choices=db_types, default=db_types[0], help='type of database to '
                                                                                         'use for scanning')
    parser.add_argument('--scan-workers', '-sw', type=int, default=SCAN_WORKERS, help='number of worker threads '
                                                                                      'to use in the scanning '
                                                                                      'threadpool. WARNING: '
                                                                                      'settings a high value may '
                                                                                      'crash device')
    parser.add_argument('--update-workers', '-uw', type=int, default=DATABASE_WORKERS, help='number of update '
                                                                                            'workers to use for '
                                                                                            'updating database, '
                                                                                            'etc. WARNING: '
                                                                                            'setting a high value '
                                                                                            'may crash device')
    parser.add_argument('--update-chunksize', '-uc', type=int, default=UPDATE_CHUNKSIZE, help='number of files to '
                                                                                              'dedicate to each '
                                                                                              'thread of a database '
                                                                                              'update')
    parser.add_argument('--update-database', '-u', action='store_true', default=False, help='update the database')
    parser.add_argument('--file-chunksize', '-f', type=int, default=FILE_CHUNKSIZE, help='number of files per '
                                                                                         'threadpool'
                                                                                         'thread for '
                                                                                         'scanning. None for '
                                                                                         'automatic selection of '
                                                                                         'chunksize')
    parser.add_argument('--scan-load-chunksize', '-lc', type=int, default=LOAD_CHUNKSIZE, help='number of bytes to '
                                                                                               'load per iteration '
                                                                                               'for each file during '
                                                                                               'scanning to prevent '
                                                                                               'potential memory '
                                                                                               'crash. None for '
                                                                                               'loading files all at '
                                                                                               'once')
    parser.add_argument('--scan-type', '-st', choices=scan_types, default=scan_types[0],
                        help='type of scan to performs')
    parser.add_argument('--path', '-p', type=str, default=None, help='the path to scan (only applicable for '
                                                                     '--scan-type={})'.format(scan_types[0]))
    parser.add_argument('--no-gpu', '-g', action='store_true', default=False, help='disable use GPU when applicable ('
                                                                                   'such as for neural-network '
                                                                                   'based databases)')
    parser.add_argument('--no-scan-side-calc', '-nc', action='store_true', default=False, help='disable thread-side '
                                                                                               'calculations for '
                                                                                               'individual files')
    parser.add_argument('--log-level', '-l', choices=['info'])
    parser.add_argument('--run-cli', '-cli', action='store_true', default=False, help='run the command line interface '
                                                                                      '(CLI)')
    parser.add_argument('--no-display-infected', '-ni', action='store_true', default=False, help='disable printing of '
                                                                                                 'infected file '
                                                                                                 'results '
                                                                                                 'at the end of a scan '
                                                                                                 'when not using CLI')
    parser.add_argument('--no-scan-archives', '-na', action='store_true', default=False, help='disable the scanning '
                                                                                              'of archives during '
                                                                                              'scanning')
    return parser.parse_args()


def main():
    start = 0

    DB_TYPES = {
        'hash': HashDatabase
    }
    if TORCH_REQUIRED:
        DB_TYPES.update({'neuralnet': NNDatabase})

    SCAN_TYPES = {
        'normal': normal_scan,
        'memory': memory_scan,
        'quick': quick_scan,
        'system': system_scan,
        'recent': recent_query
    }

    args = _get_args(list(DB_TYPES.keys()), list(SCAN_TYPES.keys()))

    if args.scan_type == list(SCAN_TYPES.keys())[0]:
        if not args.path and not args.run_cli:
            raise ValueError('No path was supplied for scan type {}.'.format(args.scan_type))
        scan = SCAN_TYPES[args.scan_type](args.path)
    else:
        scan = SCAN_TYPES[args.scan_type]()

    try:
        database = DB_TYPES[args.database.lower()]
    except KeyError:
        raise ValueError('Unsupported database type {}'.format(args.database))
    if database == NNDatabase:
        database = database(gpu=not args.no_gpu, thread_safe=False, load=False,
                            scan_side_calc=not args.no_scan_side_calc)
    elif database == HashDatabase:
        database = database(load=False, update_workers=args.update_workers, update_chunksize=args.update_chunksize)
    if args.update_database and database.updatable:
        print('Updating database...')
        database.update_obj.check().apply(load_into_memory=False)

    print('Loading database...')
    database.load(block=True)
    scanner = Scanner(database, workers=args.scan_workers,
                      file_chunksize=args.file_chunksize,
                      load_chunksize=args.scan_load_chunksize,
                      scan_archives=not args.no_scan_archives)

    def _is_list(all_files) -> bool:
        return isinstance(all_files, list)

    def print_scan_status(**kwargs):
        if _is_list(scanner.all_files):
            print(f'\rScanned {len(scanner.files)}/{len(scanner.all_files)} files ({len(scanner.results)} items)'
                  f' and found {len(scanner.infected)} threats ({round(utils.timesince(start), 1)} seconds)', **kwargs)
        else:
            print(f'\rScanned {len(scanner.results)} items and found {len(scanner.infected)} threats '
                  f'({round(utils.timesince(start), 1)} seconds)', **kwargs)

    def print_eta():
        if not _is_list(scanner.all_files): return
        print(f' Remaining: {round(utils.estimate_time(len(scanner.all_files), len(scanner.files), start), 1)}s\t\t',
              end='', flush=True)

    def print_infected():
        print()
        [print(result) for result in scanner.infected]

    try:
        while True:
            if args.run_cli:
                scan = normal_scan(input('\nDirectory/file to scan: '))
            start = time.time()
            print('Loading files to scan...')
            try:
                for res in iter(scanner.scan(scan)):
                    if not res: continue
                    if args.display_text:
                        print(f"{'infected' if res.malicious else 'clean'}: {res.path}")
                    else:
                        print_scan_status(end='', flush=True)
                        print_eta()
            except (KeyboardInterrupt, EOFError):
                scanner.stop_scan()
                print('\nScan stopped.')

            if args.display_text:
                print()
                print_scan_status(end='\t\t\n')
            if len(scanner.infected) > 0:
                if args.run_cli and utils.check_yes('\nShow potentially infected files? (y/n) '):
                    print_infected()
                elif not args.no_display_infected:
                    print_infected()
            if not args.run_cli:
                break
    except (KeyboardInterrupt, EOFError):
        print('\nExiting...')


if __name__ == '__main__':
    main()

    '''
    import sys

    # database = NNDatabase(gpu=True, thread_safe=False, load=False, scan_side_calc=True)
    database = HashDatabase()
    got_args = len(sys.argv) > 1
    if got_args:

        scanner = Scanner(database)
        display = True
    else:
        workers = int(utils.default_setting('Workers', SCAN_WORKERS))
        chunksize = utils.default_setting('Chunksize', FILE_CHUNKSIZE)
        if chunksize is not None:
            chunksize = int(chunksize)
        display = _DISPLAY
        if utils.check_yes('Display scan text? (y/n) '):
            display = True
        scanner = Scanner(database, workers=workers, file_chunksize=chunksize)
        if database.updatable:
            if utils.check_yes('Update database? (y/n) '):
                try:
                    update = database.update_obj
                    update.check()
                    if update.available:
                        update.apply(load_into_memory=False)
                except KeyboardInterrupt:
                    pass

    print('Loading database...')
    database.load(True)


    def print_scan_end(**kwargs):
        print(f'\rScanned {len(scanner.files)}/{len(scanner.all_files)} files and found {len(scanner.infected)} '
              f'threats ({round(utils.timesince(start), 1)} seconds)', **kwargs)


    def print_eta():
        print(f' Remaining: {round(utils.estimate_time(len(scanner.all_files), len(scanner.files), start), 1)}s\t\t',
              end='', flush=True)


    try:
        while True:
            mem = False
            displayed_num = False
            if got_args:
                path = sys.argv[1]
            else:
                path = input('\nDirectory/file to scan: ')
            if path.lower() in 'm mem memory ram'.split():
                mem = True
            if os.path.exists(path) or mem:
                start = time.time()
                try:
                    for res in scanner.scan(path) if not mem else scanner.memory_scan():
                        if mem and not displayed_num:
                            print(f'Scanning {len(scanner.all_files)} files in memory.')
                            displayed_num = True
                        if display:
                            print(f"{'infected' if res.malicious else 'clean'}: {res.path}")
                        else:
                            print_scan_end(end='', flush=True)
                            print_eta()
                except (KeyboardInterrupt, EOFError):
                    scanner.stop_scan()
                    print('\nScan stopped.')
                if display:
                    print()
                    print_scan_end(end='\t\t\n')
                if len(scanner.infected) > 0:
                    if not got_args and utils.check_yes('Show potentially infected files? (y/n) '):
                        [print(result) for result in scanner.infected]
            else:
                print('The path entered does not exist.')
            if got_args:
                break
    except (KeyboardInterrupt, EOFError):
        print('\nExiting...')
    '''
