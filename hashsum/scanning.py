from hashsum import SCAN_WORKERS, TORCH_REQUIRED, FILE_CHUNKSIZE, SCAN_CHUNKSIZE, IS_WINDOWS, SYSTEM_ROOT, \
    UPDATE_WORKERS
from hashsum import utils
from hashsum.database import BaseDatabase, DatabaseResult
from hashsum.errors import READ_ERRORS, ScanError
from typing import List, Iterator, Iterable, Callable, Any, Union, Tuple
from threading import Thread, Lock
from queue import Queue
from concurrent.futures import ProcessPoolExecutor, Future
from functools import partial

import sys
import atexit
import itertools
import pickle
import os
import multiprocessing as mp

_SENTINEL = object()

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


def _process_chunk(chunk: Iterable[str], calc_func: Callable[[str, Any], Any], calc_args: tuple,
                   calc_kwargs: dict, pipe_conn: mp.connection.PipeConnection):
    for file in chunk:
        pipe_conn.send(calc_func(file, *calc_args, **calc_kwargs))


class _FileIterator(object):
    def __init__(self, paths: List[str], file_iterator: Callable[[Iterable[str]], Iterator[str]],
                 scan_memory: bool, log_errors: bool):
        self.paths = paths
        self.file_iterator = file_iterator
        self.scan_memory = scan_memory
        self.log_errors = log_errors
        self.lock = Lock()

    def __iter__(self):
        with self.lock:
            if self.paths:
                yield from self.file_iterator(self.paths)
            if self.scan_memory:
                yield from self.file_iterator(utils.get_mem_files(self.log_errors))


class BaseScanner(object):
    STATE_IDLE = 0
    STATE_LOAD_PATHS = 1
    STATE_SCANNING = 2
    STATE_STOPPING = 3

    def __init__(self, database: BaseDatabase = None):
        self._state = self.STATE_IDLE
        self.__result_q = Queue()
        self.__lookup_q = None
        self._scan_thread = None
        self._db_type = None
        self._file_iter = []
        self._results = []
        if database:
            self.connect(database)

    def connect(self, database: BaseDatabase) -> None:
        self._db_type = type(database)
        self.__lookup_q = database.connect(self.__result_q)
        database.start_lookup()

    def _reset_vars(self):
        self._file_iter = []
        self._results = []

    @property
    def is_connected(self) -> bool:
        return self.__lookup_q is not None

    @property
    def file_iter(self):
        return iter(self._file_iter)

    @property
    def results(self):
        return self._results.copy()

    @property
    def state(self) -> int:
        return self._state

    def _set_state(self, state: int) -> None:
        self._state = state

    def _reset_state(self):
        self._state = self.STATE_IDLE

    def __check_connected(self):
        if not self.is_connected:
            raise ValueError('The scanner is not connected to a database, lookup is not available.')

    def _submit(self, lookup_args):
        # self.__check_connected()
        self.__lookup_q.put(lookup_args)

    def _get_result(self, block=True) -> DatabaseResult:
        # self.__check_connected()
        return self.__result_q.get(block)

    def scan(self, *args, **kwargs):
        self._reset_state()
        self._reset_vars()


class Scanner(BaseScanner):
    def __init__(self, database: BaseDatabase = None, workers: int = SCAN_WORKERS, scan_chunksize: int = None,
                 log_errors=False, *calc_args, **calc_kwargs):
        super().__init__(database)
        self.workers = workers
        self.scan_chunksize = scan_chunksize
        self.log_errors = log_errors
        self.calc_args = calc_args
        self.calc_kwargs = calc_kwargs

    @staticmethod
    def __submit_paths(calc_func: Callable[[str, Any], Any], calc_args: tuple, calc_kwargs: dict,
                       future_q: Queue, done_q: Queue, files: Iterable[str], executor: ProcessPoolExecutor):
        for file in files:
            if not done_q.empty():
                done_q.get()
                break
            try:
                future_q.put(executor.submit(calc_func, file, *calc_args, **calc_kwargs))
            except RuntimeError:
                break
        else:
            future_q.put(_SENTINEL)

    def scan(self, paths: List[str] = None, scan_memory=False,
             file_iterator: Callable[[Iterable[str]], Iterator[str]] = utils.iter_all_files,
             load_paths_while_scanning=False, *calc_args, **calc_kwargs) -> Iterator[DatabaseResult]:
        if not paths and not scan_memory:
            raise ValueError('No paths or memory to scan.')

        super().scan()
        self._set_state(self.STATE_LOAD_PATHS)

        files = _FileIterator(paths, file_iterator, scan_memory, self.log_errors)
        if not load_paths_while_scanning:
            files = list(files)
            if self.scan_chunksize:
                chunksize = self.scan_chunksize
            else:
                chunksize, extra = divmod(len(files), self.workers)
                if extra:
                    chunksize += 1

            chunks = list(utils.iter_chunks(chunksize, files))
            # print(f'Created chunks of size {chunksize}\n')
        self._file_iter = files

        self._set_state(self.STATE_SCANNING)
        with ProcessPoolExecutor(max_workers=self.workers) as executor:
            if load_paths_while_scanning:
                result_q = Queue()
                done_q = Queue()
                submit_thread = Thread(
                    target=self.__submit_paths,
                    args=(self._db_type.do_calc, calc_args, calc_kwargs, result_q, done_q, files, executor),
                    daemon=True
                )
                submit_thread.start()
                fs = []

                paths_done = False
                while self.state == self.STATE_SCANNING and not (paths_done and not len(fs)):
                    if not paths_done:
                        future = result_q.get()
                        if future is _SENTINEL:
                            paths_done = True
                        else:
                            fs.append(future)

                    done_futures = []
                    for future in fs:
                        if future.done():
                            self._submit(future.result())
                            result = self._get_result()
                            yield result
                            self._results.append(result)
                            done_futures.append(future)

                    # remove futures that have been completed
                    fs = [f for f in fs if f not in done_futures]

                if self.state != self.STATE_SCANNING:
                    for future in fs:
                        future.cancel()
                    done_q.put(_SENTINEL)
                submit_thread.join()

            else:
                parent_conn, child_conn = mp.Pipe()
                fs = [executor.submit(
                    _process_chunk, chunk, self._db_type.do_calc, calc_args, calc_kwargs, child_conn
                ) for chunk in chunks]

                while self.state == self.STATE_SCANNING and not (all([f.done() for f in fs])) and not child_conn.poll():
                    self._submit(parent_conn.recv())
                    result = self._get_result()
                    yield result
                    self._results.append(result)

                if self.state != self.STATE_SCANNING:
                    for f in fs:
                        f.cancel()
                else:
                    for future in fs:
                        future.result()
                parent_conn.close()
                child_conn.close()

        self._set_state(self.STATE_IDLE)

    def scan_async(self, *args, scan_func: Callable = None, **kwargs):
        if not scan_func: scan_func = self.scan
        self._scan_thread = Thread(target=scan_func, args=args, kwargs=kwargs, daemon=True)
        self._scan_thread.start()

    def stop_scan(self, block=True):
        if self.state == self.STATE_STOPPING or self.state == self.STATE_IDLE:
            return

        self._set_state(self.STATE_STOPPING)
        if block and self._scan_thread is not None:
            self._scan_thread.join()
        self._scan_thread = None

    # -------- Scan types --------
    def memory_scan(self, *args, **kwargs) -> Iterator[DatabaseResult]:
        return self.scan(None, True, *args, **kwargs)

    def quick_scan(self, *args, **kwargs) -> Iterator[DatabaseResult]:
        if IS_WINDOWS:
            yield from self.scan([PROGRAM_FILES, PROGRAM_FILES_86], True,
                                 file_iterator=partial(utils.iter_recent_files, hours=_DAY, modified=False, subdirs=True),
                                 *args, **kwargs)
            yield from self.scan([WINDOWS], False,
                                 file_iterator=partial(utils.iter_recent_files, hours=_FIVE_DAYS, modified=False,
                                                       subdirs=False),
                                 *args, **kwargs)
        else:
            return self.scan([
                os.path.join(SYSTEM_ROOT, 'bin'),
                os.path.join(SYSTEM_ROOT, 'sbin'),
                os.path.join(SYSTEM_ROOT, 'usr'),
                os.path.join(SYSTEM_ROOT, 'home')
            ], True,
                file_iterator=partial(utils.iter_recent_files, _FIVE_DAYS, modified=False, subdirs=True),
                *args, **kwargs)

    def system_scan(self, *args, **kwargs) -> Iterator[DatabaseResult]:
        return self.scan([SYSTEM_ROOT], True,
                         file_iterator=partial(utils.iter_recent_files, _FIVE_DAYS * 2, modified=False, subdirs=True),
                         *args, **kwargs)

    def recent_scan(self, paths: List[str] = None, *args, **kwargs) -> Iterator[DatabaseResult]:
        return self.scan(paths, scan_memory=paths is None,
                         file_iterator=partial(utils.iter_recent_files, _DAY, modified=False, subdirs=True),
                         *args, **kwargs)


def _get_args(db_types: List[str], scan_types: List[str]):
    from hashsum import DATABASE_WORKERS, UPDATE_CHUNKSIZE
    import argparse

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     description='HashSum command line interface.')
    parser.add_argument('--display-results', '-d', action='store_true', default=False,
                        help='display scan result for each individual item')
    parser.add_argument('--database', '-db', choices=db_types, default=db_types[0],
                        help='type of database to use for scanning')
    parser.add_argument('--db-workers', '-dw', type=int, default=DATABASE_WORKERS,
                        help='number of database workers to use for lookup')
    parser.add_argument('--scan-workers', '-sw', type=int, default=SCAN_WORKERS,
                        help='number of worker process to use in the scanning pool. WARNING: No limit, setting a high '
                             'value may crash device')
    parser.add_argument('--update-workers', '-uw', type=int, default=UPDATE_WORKERS,
                        help='number of update workers to use for updating database, etc. WARNING: No limit, setting '
                             'a high value may crash device')
    parser.add_argument('--update-chunksize', '-uc', type=int, default=UPDATE_CHUNKSIZE,
                        help='number of files to dedicate to each thread of a database update')
    parser.add_argument('--update-database', '-u', action='store_true', default=False,
                        help='update the database before beginning scan')
    parser.add_argument('--scan-chunksize', '-sc', type=int, default=SCAN_CHUNKSIZE,
                        help='number of files per process for scanning. None for automatic selection of chunksize')
    parser.add_argument('--file-chunksize', '-fc', type=int, default=FILE_CHUNKSIZE,
                        help='number of bytes to load per iteration for each file during scanning to prevent potential '
                             'memory overload. None for loading files all at once')
    parser.add_argument('--scan-type', '-st', choices=scan_types, default=scan_types[0], help='type of scan to perform')
    parser.add_argument('--path', '-p', type=str, default=None,
                        help=f'the path to scan (only applicable for --scan-type={scan_types[0]})')
    parser.add_argument('--no-gpu', '-g', action='store_true', default=False,
                        help='disable use GPU when applicable (such as for neural-network based databases)')
    # parser.add_argument('--no-scan-side-calc', '-nc', action='store_true', default=False, help='disable thread-side calculations for individual files')
    parser.add_argument('--load-while-scanning', '-ls', action='store_true', default=False,
                        help='discover files in directory while scanning. Otherwise, find all files before scanning')
    parser.add_argument('--log-level', '-l', choices=['info', 'debug', 'warning', 'error', 'critical'], default='info',
                        help='log level to use')
    parser.add_argument('--log-filename', '-lf', type=str, default=None,
                        help="filename to write logs to. Default won't save any logs.")
    parser.add_argument('--run-cli', '-cli', action='store_true', default=False,
                        help='run the command line interface (CLI) after loading')
    parser.add_argument('--no-display-infected', '-ni', action='store_true', default=False,
                        help='disable printing of infected file results at the end of a scan when not using CLI')
    parser.add_argument('--scan-archives', '-a', action='store_true', default=False,
                        help='scan files contained in archives')
    return parser.parse_args()


def run_cli():
    from hashsum.database import HashDatabase, DummyDatabase
    import time
    import logging

    NEWLINE = '\n'
    DB_TYPES = {
        'hash': HashDatabase,
        'dummy': DummyDatabase
    }
    if TORCH_REQUIRED:
        from hashsum.database import NNDatabase
        DB_TYPES.update({'nn': NNDatabase})

    scanner = Scanner()

    SCAN_TYPES = {
        'normal': scanner.scan,
        'recent': scanner.recent_scan,
        'memory': scanner.memory_scan,
        'quick': scanner.quick_scan,
        'system': scanner.system_scan
    }

    args = _get_args(list(DB_TYPES.keys()), list(SCAN_TYPES.keys()))
    logging.basicConfig(filename=args.log_filename)
    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, args.log_level.upper()))
    logger.debug(f'Using args: {args}')

    scanner.scan_chunksize = args.scan_chunksize
    scanner.workers = args.scan_workers
    scanner.log_errors = (args.log_level == 'error')

    if args.database not in DB_TYPES.keys():
        logger.error(f'Unsupported database type: {args.database}')
        return
    db = DB_TYPES[args.database](workers=args.db_workers)
    logger.debug(f'Using database: {db}')

    if db.updatable:
        db.update_obj.workers = args.db_workers
        db.update_obj.chunksize = args.update_chunksize
        if args.update_database:
            logger.info('Checking for updates...')
            update = db.update_obj.check()
            if update.available:
                logger.info('New version available: %s, applying...', update.version)
                update.apply(print_download=args.log_level == 'debug')
                logger.info('Database updated to version %s', db.version)

    logger.debug(f'Initializing scan type: {args.scan_type}')
    if (
            not args.run_cli
            and (args.scan_type == list(SCAN_TYPES.keys())[0]
                 or args.scan_type == list(SCAN_TYPES.keys())[1])
    ):
        if not args.path:
            logger.error('No path was supplied for scan type %s', args.scan_type)
            return

        scan_func = partial(
            SCAN_TYPES[args.scan_type],
            paths=[args.path],
            load_paths_while_scanning=args.load_while_scanning,
            scan_archive_files=args.scan_archives,
            file_load_chunksize=args.file_chunksize // scanner.workers
        )
    else:
        scan_func = partial(
            SCAN_TYPES[args.scan_type],
            load_paths_while_scanning=args.load_while_scanning,
            scan_archive_files=args.scan_archives,
            file_load_chunksize=args.file_chunksize // scanner.workers
        )

    logger.info('Loading database...')
    db.load()
    logger.debug('Connecting to scanner...')
    scanner.connect(db)

    def display_stats(start_time, num_scanned_files, detected_files, num_total_files=0):
        if not num_total_files:
            num_total_files = ''
        else:
            num_total_files = f'/{num_total_files} ({round(num_scanned_files / num_total_files * 100, 1)}%)'
        display = f'{NEWLINE if args.display_results else ""}Scanned : {num_scanned_files}{num_total_files}, ' \
                  f'detected : {len(detected_files)}, elapsed : {round(utils.timesince(start_time), 1)}s'

        if not args.load_while_scanning:
            display += f', ETA : {round(utils.estimate_time(total_files, scanned, start_time), 1)}s'

        print(display, end='\r')

    def display_scan_results(start_time, num_scanned_files, detected_files):
        print()
        logger.info(f'Scanned {num_scanned_files} files and detected {len(detected_files)} '
                    f'malicious files in {round(utils.timesince(start_time), 1)}s.')

        if detected_files and (utils.check_yes('Show detected files?') if args.run_cli else not args.no_display_infected):
            for result in detected_files:
                if result.is_archive:
                    display_result = result
                    del display_result.details['archive_files']
                    print(display_result)

                    for archive_result in result.details.get('archive_files', []):
                        if archive_result.malicious:
                            print('\t', archive_result)
                else:
                    print(result)

    while True:
        if args.run_cli:
            try:
                memory = False
                path = input('Path to scan: ')
                print()

                if path.lower() in 'e q exit quit'.split():
                    break
                elif path.lower() in 'm mem memory'.split():
                    memory = True
            except KeyboardInterrupt:
                print()
                break

        try:
            detected = []
            scanned = 0
            total_files = 0
            start = time.time()

            if not args.load_while_scanning:
                logger.info('Loading paths...')

            for result in (
                    scan_func([path] if not memory else None, memory)
                    if args.run_cli else scan_func()
            ):
                scanned += 1
                if result.malicious:
                    detected.append(result)
                if args.display_results:
                    print(result)

                if not args.load_while_scanning:
                    if not total_files:
                        total_files = len(list(scanner.file_iter))
                        logger.debug('Total files: %s\n', total_files)

                display_stats(start, scanned, detected, total_files)

            display_scan_results(start, scanned, detected)
            if not args.run_cli:
                break
        except KeyboardInterrupt:
            scanner.stop_scan()
            print()
            if not args.run_cli:
                break


if __name__ == '__main__':
    run_cli()
