from hashsum import utils
from platform import platform

import os


IS_WINDOWS = 'windows' in platform().lower()
if IS_WINDOWS:
    SYSTEM_ROOT = os.environ['SYSTEMDRIVE'] + '\\'
else:
    SYSTEM_ROOT = '/'

VERSION_FILENAME = 'db_version.pkl'
DATABASE_FILENAME = 'hash.db'
CLASSIFIER_FILENAME = 'classifier.db'  # 'densenet_loss_0.154_acc_0.966.pkl'
DATABASE_URL = 'https://virusshare.com/hashfiles/VirusShare_{}.md5'
SCAN_PATH_WILDCARD = '*'
EMPTY_HASH = utils.hash_from_str('d41d8cd98f00b204e9800998ecf8427e')
HASH_LENGTH = 16
HASH_LINE_SIZE = HASH_LENGTH + 1
NUM_SIGNATURES_1 = 131072
NUM_FILES_1 = 149
NUM_SIGNATURES_2 = 65536
TORCH_REQUIRED = True
BATCH_SIZE = 48
ARCHIVE_DELIMITER = '|'

SCAN_WORKERS = 2
DATABASE_WORKERS = 4
UPDATE_WORKERS = 4
FILE_CHUNKSIZE = 1000 * 1024 * 1024   # Max bytes to read in memory at once in total, None = All at once (default=1GB)
SCAN_CHUNKSIZE = None   # Num files, None = Auto
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
SETTINGS_FILENAME = 'settings.json'
REPORT_FILENAME = 'HashSumScanReport.txt'
REPORT_TITLE = 'HashSum by Kevi Aday Scan Report'

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
