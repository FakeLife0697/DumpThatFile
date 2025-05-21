from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.supabase_client import getPublicClient, getAdminClient
from app.modules.validation import validate_email
from functools import wraps
from datetime import datetime, timedelta

login_bp = Blueprint('login', __name__)

def is_admin(user_id):
    admin_client = getAdminClient()
    if admin_client:
        result = admin_client.schema('dtf_secure_info').table('roles').select('role').eq('user_id', user_id).execute()
        return result.data and result.data[0]['role'] == 'admin'
    return False

def check_session_activity():
    """Check if the session is still active and update last activity timestamp"""
    if 'user' in session:
        try:
            last_activity = datetime.fromisoformat(session['user']['last_activity'])
            if datetime.now(datetime.UTC) - last_activity > timedelta(minutes = 30):
                session.clear()
                flash('Your session has expired. Please log in again.', 'error')
                return False
            # Update last activity timestamp
            session['user']['last_activity'] = datetime.now(datetime.UTC).isoformat()
            return True
        except (ValueError, KeyError):
            session.clear()
            flash('Invalid session. Please log in again.', 'error')
            return False
    return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login.login'))
        
        # Check session activity
        if not check_session_activity():
            return redirect(url_for('login.login'))
            
        return f(*args, **kwargs)
    return decorated_function

@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Validate email
        is_valid_email, email_message = validate_email(email)
        if not is_valid_email:
            flash(email_message, 'error')
            return redirect(request.url)
        
        try:
            client = getPublicClient()
            response = client.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            
            if response.user:
                # Store only the necessary user data in session
                session.permanent = True  # Enable session timeout
                session['user'] = {
                    'id': response.user.id,
                    'email': response.user.email,
                    'user_metadata': response.user.user_metadata,
                    'last_activity': datetime.now(datetime.UTC).isoformat()
                }
                session['access_token'] = response.session.access_token
                
                # Check if user is admin
                if is_admin(response.user.id):
                    return redirect(url_for('admin.admin_dashboard'))
                return redirect(url_for('home.home'))
                
        except Exception as e:
            flash('Invalid email or password', 'error')
            print(e)
            
    return render_template('login.html')

@login_bp.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    return redirect(url_for('login.login'))
