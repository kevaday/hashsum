from zipfile import error
from tarfile import ReadError
class UpdateNotAvailableError(Exception): pass
class LoadError(Exception): pass
class ScanError(IOError): pass
READ_ERRORS = (OSError, IOError, PermissionError, error, ReadError)
