import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime, timezone

def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    log_path = os.path.join(os.path.dirname(__file__), 'DTFlogs')
    os.makedirs(log_path, exist_ok = True)
    print("Log path: " + log_path)
    
    # Create a formatter
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(name)s: %(message)s'
    )
    
    # Create a file handler for all logs
    all_handler = RotatingFileHandler(
        filename = log_path + '/all.log',
        maxBytes = 1024 * 1024 * 16,  # 16MB
        backupCount = 10,
        encoding = 'utf-8'
    )
    all_handler.setLevel(logging.INFO)
    all_handler.setFormatter(formatter)
    
    # Create a file handler for errors
    error_handler = RotatingFileHandler(
        filename = log_path + '/error.log',
        maxBytes = 1024 * 1024 * 16,  # 16MB
        backupCount = 10,
        encoding = 'utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    
    # Create a file handler for security events
    security_handler = RotatingFileHandler(
        filename = log_path + '/security.log',
        maxBytes = 1024 * 1024 * 16,  # 16MB
        backupCount = 10,
        encoding = 'utf-8'
    )
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(formatter)
    
    # Add handlers to the app logger
    logger.addHandler(all_handler)
    logger.addHandler(error_handler)
    logger.addHandler(security_handler)
    
    return logger

def log_security_event(logger, event_type, details, level = logging.WARNING):
    logger.log(level, f"SECURITY EVENT - {event_type}: {details}")

def log_auth_event(logger, event_type, user_id = None, ip_address = None, success = True):
    details = {
        'event': event_type,
        'user_id': user_id,
        'ip_address': ip_address,
        'success': success,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    logger.warning(f"AUTH EVENT: {details}") 

print(os.path.join(os.path.dirname(__file__), 'DTFlogs'))