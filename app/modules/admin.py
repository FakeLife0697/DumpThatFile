from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify, flash
from app.modules.login import login_required, check_session_activity
from app.modules.home import login_required
from app.modules.encrypt import SHA256, AES, RSA
from app.supabase_client import getPublicClient, getAdminClient
from functools import wraps
import uuid
import os

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login.login'))
            
        # Check session activity
        if not check_session_activity():
            return redirect(url_for('login.login'))
            
        if not (session['user']['role'] == 'admin'):
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('home.home'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/logout', methods=['GET'])
@login_required
def logout():
    try:
        client = getPublicClient()
        client.auth.sign_out()
        session.clear()
        return redirect(url_for('index.index'))
    except Exception as e:
        print(f"Error during logout: {str(e)}")
        session.clear()
        return redirect(url_for('index.index'))

@admin_bp.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin.html')

@admin_bp.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    try:
        client = getAdminClient()
        result = client.schema('public').table('users').select('*').execute()
        return jsonify(result.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/files', methods=['GET'])
@login_required
@admin_required
def get_files():
    try:
        client = getAdminClient()
        result = client.schema('public').table('files').select('*').execute()
        return jsonify(result.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/friends', methods=['GET'])
@login_required
@admin_required
def get_friends():
    try:
        client = getAdminClient()
        result = client.schema('public').table('friends').select('*').execute()
        return jsonify(result.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/signatures', methods=['GET'])
@login_required
@admin_required
def get_signatures():
    try:
        client = getAdminClient()
        result = client.schema('public').table('signatures').select('*').execute()
        return jsonify(result.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/roles', methods=['GET'])
@login_required
@admin_required
def get_roles():
    try:
        client = getAdminClient()
        result = client.schema('dtf_secure_info').table('roles').select('*').execute()
        return jsonify(result.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/keys', methods=['GET'])
@login_required
@admin_required
def get_keys():
    try:
        client = getAdminClient()
        result = client.schema('dtf_secure_info').table('user_keys').select('*').execute()
        return jsonify(result.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

