from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from app.supabase_client import getPublicClient, getAdminClient
from app.modules.validation import validate_email
from app.logger import log_auth_event, log_security_event
from functools import wraps
from datetime import datetime, timedelta, timezone

login_bp = Blueprint('login', __name__)

def check_session_activity():
    # Check if the session is still active and update last activity timestamp
    if 'user' in session:
        try:
            last_activity = datetime.fromisoformat(session['user']['last_activity'])
            if datetime.now(timezone.utc) - last_activity > timedelta(minutes = 30):
                session.clear()
                flash('Your session has expired. Please log in again.', 'error')
                log_security_event(current_app.logger, 'SESSION_EXPIRED', {
                    'user_id': session.get('user', {}).get('id')
                })
                return False
            # Update last activity timestamp
            session['user']['last_activity'] = datetime.now(timezone.utc).isoformat()
            return True
        except (ValueError, KeyError):
            session.clear()
            flash('Invalid session. Please log in again.', 'error')
            log_security_event(current_app.logger, 'INVALID_SESSION', {
                'user_id': session.get('user', {}).get('id')
            })
            return False
    return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'error')
            log_security_event(current_app.logger, 'UNAUTHORIZED_ACCESS', {
                'ip': request.remote_addr, 
                'path': request.path
            })
            return redirect(url_for('login.login'))
        
        # Check session activity
        if not check_session_activity():
            return redirect(url_for('login.login'))
            
        return f(*args, **kwargs)
    return decorated_function

@login_bp.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Validate email
        is_valid_email, email_message = validate_email(email)
        if not is_valid_email:
            flash(email_message, 'error')
            log_security_event(
                current_app.logger, 'INVALID_EMAIL', {
                    'email': email, 
                    'ip': request.remote_addr
                })
            return redirect(request.url)
        
        try:
            client = getPublicClient()
            response = client.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            
            if response.user:
                admin_client = getAdminClient()
                
                # Check if user exists in our custom tables
                user_result = admin_client.schema('public').table('users').select('*').eq('user_id', response.user.id).execute()
                
                if not user_result.data:
                    # User doesn't exist in our tables, insert their data
                    try:
                        # Insert into users table
                        admin_client.schema('public').table('users').insert({
                            'user_id': response.user.id,
                            'email': response.user.email,
                            'username': response.user.user_metadata.get('username', email.split('@')[0]),
                            'public_key': None
                        }).execute()
                        
                        # Insert into roles table with default 'user' role
                        admin_client.schema('dtf_secure_info').table('roles').insert({
                            'user_id': response.user.id,
                            'role': 'user'
                        }).execute()
                        
                        # Log the data insertion
                        log_auth_event(
                            current_app.logger, 'USER_DATA_CREATED_ON_SIGNIN', 
                            user_id = response.user.id,
                            ip_address = request.remote_addr
                        )
                    except Exception as e:
                        current_app.logger.error(f"Error creating user data: {str(e)}")
                        flash('Error setting up user data. Please try again.', 'error')
                        return redirect(request.url)
                
                # Get user's role
                role_result = admin_client.schema('dtf_secure_info').table('roles').select('role').eq('user_id', response.user.id).execute()
                user_role = role_result.data[0]['role'] if role_result.data else 'user'
                
                # Store only the necessary user data in session
                session.permanent = True  # Enable session timeout
                session['user'] = {
                    'id': response.user.id,
                    'email': response.user.email,
                    'user_metadata': response.user.user_metadata,
                    'role': user_role,
                    'last_activity': datetime.now(timezone.utc).isoformat()
                }
                session['access_token'] = response.session.access_token
                
                # Log successful login
                log_auth_event(
                    current_app.logger, 'LOGIN_SUCCESS', 
                    user_id = response.user.id,
                    ip_address = request.remote_addr
                )
                
                return redirect(url_for('home.home'))
                
        except Exception as e:
            flash(f'Invalid email or password: {str(e)}', 'error')
            # Log failed login attempt
            log_auth_event(
                current_app.logger, 'LOGIN_FAILED', 
                ip_address = request.remote_addr,
                success = False
            )
            current_app.logger.error(f"Login error: {str(e)}")
            
    return render_template('login.html')

@login_bp.route('/logout')
def logout():
    if 'user' in session:
        # Log logout event
        log_auth_event(
            current_app.logger, 'LOGOUT', 
            user_id = session['user']['id'],
            ip_address = request.remote_addr
        )
    
    # Clear all session data
    session.clear()
    return redirect(url_for('login.login'))
