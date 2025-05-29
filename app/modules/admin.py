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
        session.clear()
        flash(f'Admin logout error: {str(e)}', 'error')
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
        # Get all files
        files_result = client.table('files').select('*').execute()
        
        # Get all users for lookup
        users_result = client.table('users').select('user_id, username, email').execute()
        users_dict = {user['user_id']: user for user in users_result.data}
        
        # Transform the data to include user information
        transformed_data = []
        for file in files_result.data:
            sender_info = users_dict.get(file['sender'], {'username': 'Unknown', 'email': 'Unknown'})
            receiver_info = users_dict.get(file['receiver'], {'username': 'Unknown', 'email': 'Unknown'})
            
            transformed_file = {
                'file_id': file['file_id'],
                'file_path': file['file_path'],
                'file_name': file['file_name'],
                'creating_date': file['creating_date'],
                'expiring_date': file['expiring_date'],
                'sender': {
                    'username': sender_info['username'],
                    'email': sender_info['email']
                },
                'receiver': {
                    'username': receiver_info['username'],
                    'email': receiver_info['email']
                }
            }
            transformed_data.append(transformed_file)
        
        return jsonify(transformed_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/friends', methods=['GET'])
@login_required
@admin_required
def get_friends():
    try:
        client = getAdminClient()
        # Get all friendships
        friends_result = client.table('friends').select('*').execute()
        
        # Get all users for lookup
        users_result = client.table('users').select('user_id, username, email').execute()
        users_dict = {user['user_id']: user for user in users_result.data}
        
        # Transform the data to include user information
        transformed_data = []
        for friendship in friends_result.data:
            user_info = users_dict.get(friendship['user_id'], {'username': 'Unknown', 'email': 'Unknown'})
            friend_info = users_dict.get(friendship['friend_id'], {'username': 'Unknown', 'email': 'Unknown'})
            
            transformed_friendship = {
                'user_id': friendship['user_id'],
                'friend_id': friendship['friend_id'],
                'users': {
                    'username': user_info['username'],
                    'email': user_info['email']
                },
                'users_1': {
                    'username': friend_info['username'],
                    'email': friend_info['email']
                }
            }
            transformed_data.append(transformed_friendship)
        
        return jsonify(transformed_data)
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
        # Get all roles
        roles_result = client.schema('dtf_secure_info').table('roles').select('*').execute()
        
        # Get all users for lookup
        users_result = client.table('users').select('user_id, username, email').execute()
        users_dict = {user['user_id']: user for user in users_result.data}
        
        # Transform the data to include user information
        transformed_data = []
        for role in roles_result.data:
            user_info = users_dict.get(role['user_id'], {'username': 'Unknown', 'email': 'Unknown'})
            
            transformed_role = {
                'user_id': role['user_id'],
                'role': role['role'],
                'users': {
                    'username': user_info['username'],
                    'email': user_info['email']
                }
            }
            transformed_data.append(transformed_role)
        
        return jsonify(transformed_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/keys', methods=['GET'])
@login_required
@admin_required
def get_keys():
    try:
        client = getAdminClient()
        # Get all user keys
        keys_result = client.schema('dtf_secure_info').table('user_keys').select('*').execute()
        
        # Get all users for lookup
        users_result = client.table('users').select('user_id, username, email').execute()
        users_dict = {user['user_id']: user for user in users_result.data}
        
        # Transform the data to include user information
        transformed_data = []
        for key in keys_result.data:
            user_info = users_dict.get(key['user_id'], {'username': 'Unknown', 'email': 'Unknown'})
            
            transformed_key = {
                'user_id': key['user_id'],
                'public_key': key['public_key'],
                'private_key': key['private_key'],
                'users': {
                    'username': user_info['username'],
                    'email': user_info['email']
                }
            }
            transformed_data.append(transformed_key)
        
        return jsonify(transformed_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def delete_file_from_storage_and_db(file_id):
    try:
        client = getAdminClient()
        
        # Get file info first
        file_result = client.table('files').select('file_path, file_id').eq('file_id', file_id).execute()
        if not file_result.data:
            return {'error': 'File not found in database'}, 404
        
        file_data = file_result.data[0]
        file_path = file_data['file_path']
        
        # Delete from storage if file_path exists
        if file_path:
            try:
                client.storage.from_('encrypted-files').remove([file_path])
            except Exception as storage_error:
                print(f"Warning: Failed to delete file from storage: {storage_error}")
        
        # Delete from database
        delete_result = client.table('files').delete().eq('file_id', file_id).execute()
        if not delete_result.data:
            return {'error': 'Failed to delete file from database'}, 500
        
        return {'message': 'File deleted successfully'}, 200
        
    except Exception as e:
        return {'error': f'Error deleting file: {str(e)}'}, 500

def delete_signature_from_storage_and_db(signature_id):
    try:
        client = getAdminClient()
        
        # Get signature info first
        signature_result = client.table('signatures').select('sign_path, sign_id').eq('sign_id', signature_id).execute()
        if not signature_result.data:
            return {'error': 'Signature not found in database'}, 404
        
        signature_data = signature_result.data[0]
        sign_path = signature_data['sign_path']
        
        # Delete from storage if sign_path exists
        if sign_path:
            try:
                client.storage.from_('signature-files').remove([sign_path])
            except Exception as storage_error:
                print(f"Warning: Failed to delete signature from storage: {storage_error}")
        
        # Delete from database
        delete_result = client.table('signatures').delete().eq('sign_id', signature_id).execute()
        if not delete_result.data:
            return {'error': 'Failed to delete signature from database'}, 500
        
        return {'message': 'Signature deleted successfully'}, 200
        
    except Exception as e:
        return {'error': f'Error deleting signature: {str(e)}'}, 500

@admin_bp.route('/admin/delete-file/<file_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_file_endpoint(file_id):
    result, status_code = delete_file_from_storage_and_db(file_id)
    return jsonify(result), status_code

@admin_bp.route('/admin/delete-signature/<signature_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_signature_endpoint(signature_id):
    result, status_code = delete_signature_from_storage_and_db(signature_id)
    return jsonify(result), status_code

