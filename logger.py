import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime

def get_timestamp():
    """Generate timestamp dengan format yang konsisten"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def setup_logger(name, log_file='app.log'):
    # Buat direktori logs jika belum ada
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Setup format logging
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)-8s %(name)-12s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup handler untuk file
    file_handler = RotatingFileHandler(
        os.path.join('logs', log_file),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    
    # Setup logger
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    
    return logger
