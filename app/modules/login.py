from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.supabase_client import getPublicClient, getAdminClient
from functools import wraps

login_bp = Blueprint('login', __name__)

def is_admin(user_id):
    admin_client = getAdminClient()
    if admin_client:
        result = admin_client.schema('dtf_secure_info').table('roles').select('role').eq('user_id', user_id).execute()
        return result.data and result.data[0]['role'] == 'admin'
    return False

@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            client = getPublicClient()
            response = client.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            
            if response.user:
                # Store only the necessary user data in session
                session["user"] = {
                    "id": response.user.id,
                    "email": response.user.email,
                    "user_metadata": response.user.user_metadata
                }
                session["access_token"] = response.session.access_token
                
                # Check if user is admin
                if is_admin(response.user.id):
                    return redirect(url_for('admin.admin_dashboard'))
                return redirect(url_for('home.home'))
                
        except Exception as e:
            flash('Invalid email or password', 'error')
            print(e)
            
    return render_template('login.html')
