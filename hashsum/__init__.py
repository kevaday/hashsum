from platform import platform

import os


IS_WINDOWS = 'windows' in platform().lower()
if IS_WINDOWS:
    SYSTEM_ROOT = os.environ['SYSTEMDRIVE'] + '\\'
else:
    SYSTEM_ROOT = '/'

VERSION_FILENAME = 'db.version'
DATABASE_FILENAME = 'hash.db'
CLASSIFIER_FILENAME = 'classifier.db'  # 'densenet_loss_0.154_acc_0.966.pkl'
SETTINGS_FILENAME = 'settings.json'
REPORT_FILENAME = 'HashSumScanReport.txt'
REPORT_TITLE = 'HashSum by Kevi Aday Scan Report'
DATABASE_URL = 'http://virusshare.com/hashes/VirusShare_{}.md5'
SCAN_PATH_WILDCARD = '*'
EMPTY_HASH = bytes.fromhex('d41d8cd98f00b204e9800998ecf8427e')
HASH_LINE_SIZE = 16 + 1
TORCH_REQUIRED = False
BATCH_SIZE = 48

SCAN_WORKERS = 2
DATABASE_WORKERS = 4
FILE_CHUNKSIZE = None   # Num files, None = Auto
LOAD_CHUNKSIZE = None   # Num bytes, None = All at once
UPDATE_CHUNKSIZE = 2    # Num definitions to download per thread
UPDATE_INTERVAL = 1000  # GUI update interval millis
DB_TYPE_HASH = 'MD5 Hash'
DB_TYPE_AI = 'Deep Learning'
DB_TYPE_DUMMY = 'Dummy Database'
DB_TYPES = [
    DB_TYPE_HASH,
    DB_TYPE_AI,
    DB_TYPE_DUMMY
]
ICON_FILENAME = 'icon.png'

DEFAULT_SETTINGS = {
    # HashSum settings
    'scan_subdirs': True,
    'scan_archives': True,
    'load_while_scanning': True,
    'scan_workers': SCAN_WORKERS,
    'scan_chsz': 0,
    'scan_load_chsz': 0,
    # Database settings
    'load_on_start': False,
    'data_workers': DATABASE_WORKERS,
    'update_chsz': UPDATE_CHUNKSIZE,
    'data_load_chsz': 20000000,
    'database_type': DB_TYPE_HASH,
    'use_gpu': TORCH_REQUIRED
}
