from datetime import datetime, timezone
import schedule
import time
from app.supabase_client import getAdminClient
from app.modules.admin import delete_file_from_storage_and_db, delete_signature_from_storage_and_db
import threading
from app.logger import setup_logger

# Use the existing logger system
logger = setup_logger()

def log_expiry_event(event_type, details, level = 'INFO'):
    if level.upper() == 'INFO':
        logger.info(f"EXPIRY EVENT - {event_type}: {details}")
    elif level.upper() == 'WARNING':
        logger.warning(f"EXPIRY EVENT - {event_type}: {details}")
    elif level.upper() == 'ERROR':
        logger.error(f"EXPIRY EVENT - {event_type}: {details}")

def check_and_delete_expired_files():
    try:
        client = getAdminClient()
        current_time = datetime.now(timezone.utc)
        
        # Get all files with expiring_date
        files_result = client.table('files').select('file_id, file_name, expiring_date').execute()
        
        if not files_result.data:
            log_expiry_event("FILE_CHECK", "No files found in database")
            return
        
        expired_files = []
        for file in files_result.data:
            if file['expiring_date']:
                try:
                    # Parse the expiring date and ensure it's timezone-aware
                    expire_date_str = file['expiring_date']
                    if expire_date_str.endswith('Z'):
                        expire_date_str = expire_date_str.replace('Z', '+00:00')
                    
                    expire_date = datetime.fromisoformat(expire_date_str)
                    
                    # If the date is timezone-naive, assume it's UTC
                    if expire_date.tzinfo is None:
                        expire_date = expire_date.replace(tzinfo = timezone.utc)
                    
                    if expire_date < current_time:
                        expired_files.append(file)
                except (ValueError, TypeError) as e:
                    log_expiry_event("FILE_CHECK_ERROR", f"Invalid expiring_date format for file {file['file_id']}: {e}", 'WARNING')
        
        # Delete expired files
        for file in expired_files:
            log_expiry_event("FILE_DELETE", f"Deleting expired file: {file['file_name']} (ID: {file['file_id']})")
            result, status_code = delete_file_from_storage_and_db(file['file_id'])
            if status_code == 200:
                log_expiry_event("FILE_DELETE_SUCCESS", f"Successfully deleted file: {file['file_name']}")
            else:
                log_expiry_event("FILE_DELETE_ERROR", f"Failed to delete file {file['file_name']}: {result}", 'ERROR')
        
        log_expiry_event("FILE_CHECK_COMPLETE", f"Expired files check completed. Deleted {len(expired_files)} files.")
        
    except Exception as e:
        log_expiry_event("FILE_CHECK_ERROR", f"Error checking expired files: {str(e)}", 'ERROR')

def check_and_delete_expired_signatures():
    try:
        client = getAdminClient()
        current_time = datetime.now(timezone.utc)
        
        # Get all signatures with expiring_date
        signatures_result = client.table('signatures').select('sign_id, sign_path, expiring_date').execute()
        
        if not signatures_result.data:
            log_expiry_event("SIGNATURE_CHECK", "No signatures found in database")
            return
        
        expired_signatures = []
        for signature in signatures_result.data:
            if signature['expiring_date']:
                try:
                    # Parse the expiring date and ensure it's timezone-aware
                    expire_date_str = signature['expiring_date']
                    if expire_date_str.endswith('Z'):
                        expire_date_str = expire_date_str.replace('Z', '+00:00')
                    
                    expire_date = datetime.fromisoformat(expire_date_str)
                    
                    # If the date is timezone-naive, assume it's UTC
                    if expire_date.tzinfo is None:
                        expire_date = expire_date.replace(tzinfo = timezone.utc)
                    
                    if expire_date < current_time:
                        expired_signatures.append(signature)
                except (ValueError, TypeError) as e:
                    log_expiry_event("SIGNATURE_CHECK_ERROR", f"Invalid expiring_date format for signature {signature['sign_id']}: {e}", 'WARNING')
        
        # Delete expired signatures
        for signature in expired_signatures:
            log_expiry_event("SIGNATURE_DELETE", f"Deleting expired signature: {signature['sign_path']} (ID: {signature['sign_id']})")
            result, status_code = delete_signature_from_storage_and_db(signature['sign_id'])
            if status_code == 200:
                log_expiry_event("SIGNATURE_DELETE_SUCCESS", f"Successfully deleted signature: {signature['sign_path']}")
            else:
                log_expiry_event("SIGNATURE_DELETE_ERROR", f"Failed to delete signature {signature['sign_path']}: {result}", 'ERROR')
        
        log_expiry_event("SIGNATURE_CHECK_COMPLETE", f"Expired signatures check completed. Deleted {len(expired_signatures)} signatures.")
        
    except Exception as e:
        log_expiry_event("SIGNATURE_CHECK_ERROR", f"Error checking expired signatures: {str(e)}", 'ERROR')

def check_expired_files_and_signatures():
    log_expiry_event("SCHEDULER_START", "Starting scheduled check for expired files and signatures...")
    check_and_delete_expired_files()
    check_and_delete_expired_signatures()
    log_expiry_event("SCHEDULER_COMPLETE", "Completed scheduled check for expired files and signatures.")

def run_scheduler():
    log_expiry_event("SCHEDULER_INIT", "Starting expiry check scheduler...")
    # schedule.every().day.at("00:00").do(check_expired_files_and_signatures)
    schedule.every().minute.do(check_expired_files_and_signatures)
    
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute for scheduled tasks

def start_expiry_checker():
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    log_expiry_event("SCHEDULER_INIT", "Expiry checker started in background thread")

def run_expiry_check_now():
    log_expiry_event("MANUAL_CHECK", "Running manual expiry check...")
    check_expired_files_and_signatures()