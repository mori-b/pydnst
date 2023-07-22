import sys
import os
import gzip
import time
import logging
from logging.handlers import RotatingFileHandler

PYTHON_VERSION = (sys.version_info.major,sys.version_info.minor)
if PYTHON_VERSION < (3,6):
    print('dnst_server minimum requirement : Python 3.6')
    sys.exit(1)
PYTHON_GREATER_37 = (PYTHON_VERSION >= (3,7))    


DEFAULT_LOGGER_NAME = 'pydnst'
LOGFILE_DEFAULT_PATH = 'pydnst.log'
LOG_LEVEL = 'INFO'
LOG_ROTATE = True
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FORMAT_SHORT = '%(asctime)s - %(levelname)s - %(message)s'
LOG_BK_COUNT = 5
LOG_MAX_SIZE = 67108864 # 2**26 = 64 MB

def get_logger(logfile_path=LOGFILE_DEFAULT_PATH, first_run=False, silent=True, logger_name=DEFAULT_LOGGER_NAME, 
               log_format=LOG_FORMAT, level=LOG_LEVEL, rotate=LOG_ROTATE):
    
    def namer(name):
        return name + '.gz'
    
    def rotator(source, dest):
        with open(source, 'rb') as sf:
            data = sf.read()
        compressed = gzip.compress(data)
        with open(dest, 'wb') as df:
            df.write(compressed)
        os.truncate(source, 0)
    
    logger = logging.getLogger(logger_name)
    logger.handlers = []
    if not first_run:
        handlers = []
        if logfile_path:    #could be '' if no config file provided
            if rotate:
                if rotate is True:
                    rotate = LOG_MAX_SIZE
                else:
                    #use user defined value                    
                    try:
                        rotate = int(rotate)
                    except Exception:
                        rotate = LOG_MAX_SIZE
                fh = RotatingFileHandler(logfile_path, maxBytes=rotate, backupCount=LOG_BK_COUNT)
                fh.rotator = rotator
                fh.namer = namer                
                handlers.append(fh)
            else:
                handlers.append(logging.FileHandler(logfile_path))
        if not silent:
            handlers.append(logging.StreamHandler(sys.stdout))
        if not handlers:
            logger.addHandler(logging.NullHandler())
            return logger

        log_level = getattr(logging, level, logging.INFO)
        logger.setLevel(log_level)        
        
        formatter = logging.Formatter(log_format)
        formatter.converter = time.gmtime
        for fh in handlers:
            fh.setFormatter(formatter)
            fh.setLevel(logging.DEBUG)        
            logger.addHandler(fh)
    else:
        logger.addHandler(logging.NullHandler())    
    
    return logger

