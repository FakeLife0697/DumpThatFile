from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.supabase import getPublicClient, getAdminClient

signup_bp = Blueprint('signup', __name__)

@signup_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        username = request.form.get('username')
        
        try:
            client = getPublicClient()
            # Sign up the user
            response = client.auth.sign_up({
                "email": email,
                "password": password
            })
            
            if response.user:
                # Create user record in the database
                admin_client = getAdminClient()
                admin_client.table('users').insert({
                    'user_id': response.user.id,
                    'username': username,
                    'email': email
                }).execute()
                
                # Set default role as 'user'
                admin_client.table('dtf_secure_info.roles').insert({
                    'user_id': response.user.id,
                    'role': 'user'
                }).execute()
                
                flash('Account created successfully!', 'success')
                return redirect(url_for('login.login'))
                
        except Exception as e:
            flash('Error creating account. Please try again.', 'error')
            
    return render_template('signup.html')
