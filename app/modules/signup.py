from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from app.supabase_client import getPublicClient, getAdminClient
from app.modules.encrypt import RSA
from app.modules.validation import validate_email, validate_username, validate_password
from app.logger import log_auth_event, log_security_event
import traceback
from supabase.lib.client_options import ClientOptions
import time
from requests.exceptions import Timeout, RequestException

signup_bp = Blueprint('signup', __name__)

@signup_bp.route('/signup', methods = ['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        username = request.form.get('username')
        
        # Validate all inputs
        is_valid_email, email_message = validate_email(email)
        if not is_valid_email:
            flash(email_message, 'error')
            log_security_event(current_app.logger, 'INVALID_SIGNUP_EMAIL', {
                'email': email, 
                'ip': request.remote_addr
            })
            return redirect(request.url)
            
        is_valid_username, username_message = validate_username(username)
        if not is_valid_username:
            flash(username_message, 'error')
            log_security_event(current_app.logger, 'INVALID_SIGNUP_USERNAME', {
                'username': username,
                'ip': request.remote_addr
            })
            return redirect(request.url)
            
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            flash(password_message, 'error')
            log_security_event(current_app.logger, 'INVALID_SIGNUP_PASSWORD', {
                'ip': request.remote_addr
            })
            return redirect(request.url)
        
        try:
            # First, check if username or email already exists
            client = getPublicClient()
            max_retries = 3
            retry_count = 0
            
            while retry_count < max_retries:
                try:
                    existing_user = client.schema('public').table('users').select('*').or_(
                        f'username.eq.{username},email.eq.{email}'
                    ).execute()
                    break
                except (Timeout, RequestException) as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        raise Exception(f"Database operation timed out after {max_retries} attempts: {str(e)}")
                    time.sleep(1)  # Wait 1 second before retrying
                except Exception as e:
                    raise e
            
            if existing_user.data:
                flash('Username or email already exists', 'error')
                log_security_event(current_app.logger, 'DUPLICATE_SIGNUP', 
                    {'email': email, 'username': username, 'ip': request.remote_addr})
                return redirect(request.url)
            
            # Sign up the user in Supabase Auth
            auth_response = client.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "username": username
                    }
                }
            })
            
            if not auth_response.user:
                flash('Failed to create authentication account', 'error')
                log_security_event(current_app.logger, 'SIGNUP_AUTH_FAILED', {
                    'email': email, 
                    'username': username, 
                    'ip': request.remote_addr
                })
                return redirect(request.url)
            
            # Create user record in your database
            admin_client = getAdminClient()
            retry_count = 0
            
            while retry_count < max_retries:
                try:
                    user_response = admin_client.schema('public').table('users').insert({
                        'user_id': auth_response.user.id,
                        'username': username,
                        'email': email,
                        'public_key': None
                    }).execute()

                    role_response = admin_client.schema('dtf_secure_info').table('roles').insert({
                        'user_id': auth_response.user.id,
                        'role': 'user'
                    }).execute()

                    # Log the data insertion
                    log_auth_event(
                        current_app.logger, 'USER_DATA_CREATED_ON_SIGNUP', 
                        user_id = auth_response.user.id,
                        ip_address = request.remote_addr
                    )
                    break
                except (Timeout, RequestException) as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        raise Exception(f"Database operation timed out after {max_retries} attempts: {str(e)}")
                    time.sleep(1)
                except Exception as e:
                    raise e
            
            if not user_response.data:
                flash('Failed to create user record', 'error')
                log_security_event(current_app.logger, 'USER_DATA_SIGNUP_FAILED', {
                        'user_id': auth_response.user.id, 
                        'ip': request.remote_addr
                })
                return redirect(request.url)
            
            # Log successful signup
            log_auth_event(
                current_app.logger, 
               'SIGNUP_SUCCESS', 
                user_id = auth_response.user.id,
                ip_address = request.remote_addr
            )
            
            flash('Account created successfully! Please check your email for verification.', 'success')
            return redirect(url_for('login.login'))
                
        except Exception as e:
            # Log error and flash message
            current_app.logger.error(f"Signup error: {str(e)}\n{traceback.format_exc()}")
            flash(f'Error creating account: {str(e)}', 'error')
            
    return render_template('signup.html')
