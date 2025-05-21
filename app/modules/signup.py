from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.supabase_client import getPublicClient, getAdminClient
from app.modules.encrypt import RSA
from app.modules.validation import validate_email, validate_username, validate_password
import traceback
from supabase.lib.client_options import ClientOptions
import time
from requests.exceptions import Timeout, RequestException

signup_bp = Blueprint('signup', __name__)

@signup_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        username = request.form.get('username')
        
        # Validate all inputs
        is_valid_email, email_message = validate_email(email)
        if not is_valid_email:
            flash(email_message, 'error')
            return redirect(request.url)
            
        is_valid_username, username_message = validate_username(username)
        if not is_valid_username:
            flash(username_message, 'error')
            return redirect(request.url)
            
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            flash(password_message, 'error')
            return redirect(request.url)
        
        try:
            # Configure client
            client_options = ClientOptions(
                schema='public',
                headers={'X-Client-Info': 'supabase-flask/1.0.0'}
            )
            
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
                return redirect(request.url)
            
            # Create user record in your database
            admin_client = getAdminClient()
            retry_count = 0
            
            while retry_count < max_retries:
                try:
                    user_response = admin_client.schema('public').table('users').insert({
                        'user_id': auth_response.user.id,
                        'username': username,
                        'email': email
                    }).execute()
                    break
                except (Timeout, RequestException) as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        raise Exception(f"Database operation timed out after {max_retries} attempts: {str(e)}")
                    time.sleep(1)
                except Exception as e:
                    raise e
            
            if not user_response.data:
                # If user creation fails, we should clean up the auth user
                # (You might want to implement this cleanup)
                flash('Failed to create user record', 'error')
                return redirect(request.url)
            
            # Set default role as 'user'
            retry_count = 0
            while retry_count < max_retries:
                try:
                    role_response = admin_client.schema('dtf_secure_info').table('roles').insert({
                        'user_id': auth_response.user.id,
                        'role': 'user'
                    }).execute()
                    break
                except (Timeout, RequestException) as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        raise Exception(f"Database operation timed out after {max_retries} attempts: {str(e)}")
                    time.sleep(1)
                except Exception as e:
                    raise e
            
            if not role_response.data:
                flash('Failed to set user role', 'error')
                return redirect(request.url)
            
            flash('Account created successfully! Please check your email for verification.', 'success')
            return redirect(url_for('login.login'))
                
        except Exception as e:
            # Print detailed error information for debugging
            flash(f'Error creating account: {str(e)}', 'error')
            
    return render_template('signup.html')
