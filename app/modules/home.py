from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify, flash
from functools import wraps
from flask_restful import Api
from app.supabase_client import getPublicClient, getAdminClient
from app.modules.encrypt import SHA256, AES, RSA
import uuid
import os
import time
from requests.exceptions import Timeout, RequestException

home_bp = Blueprint('home', __name__)
api = Api(home_bp)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login.login'))
        return f(*args, **kwargs)
    return decorated_function

@home_bp.route('/search-users', methods=['GET'])
@login_required
def search_users():
    query = request.args.get('query', '')
    if not query:
        return jsonify([])
    
    try:
        client = getPublicClient()
        # Search users by username or email
        result = client.table('users').select('user_id, username, email').or_(
            f'username.ilike.%{query}%,email.ilike.%{query}%'
        ).execute()
        return jsonify(result.data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@home_bp.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        receiver_id = request.form.get('receiver_id')
        if not receiver_id:
            flash('No receiver selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        # Check file size (5MB limit)
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        
        if size > 5 * 1024 * 1024:  # 5MB in bytes
            flash('File size exceeds 5MB limit', 'error')
            return redirect(request.url)
        
        try:
            # First check if they are friends
            client = getPublicClient()
            friends_result = client.table('friends').select('*').or_(
                f'user_id.eq.{session["user"]["id"]},friend_id.eq.{session["user"]["id"]}'
            ).and_(
                f'user_id.eq.{receiver_id},friend_id.eq.{receiver_id}'
            ).execute()
            
            if not friends_result.data:
                flash('You can only send files to your friends', 'error')
                return redirect(request.url)
            
            # Get receiver's public key
            key_result = client.schema('public').table('users').select('public_key').eq('user_id', receiver_id).execute()
            
            if not key_result.data:
                flash('Receiver has no valid public key', 'error')
                return redirect(request.url)
            
            receiver_public_key = key_result.data[0]['public_key']
            
            # Generate unique IDs
            file_id = str(uuid.uuid4())
            sign_id = str(uuid.uuid4())
            
            # Create signature
            sha256 = SHA256()
            signature = sha256.hash(file.read())
            file.seek(0)  # Reset file pointer
            
            # Generate and encrypt with AES
            aes = AES()
            aes_key = aes.generate_key()
            encrypted_file = aes.encrypt(file.read())
            file.seek(0)  # Reset file pointer
            
            # Encrypt AES key with receiver's public key
            rsa = RSA()
            encrypted_aes_key = rsa.encrypt(aes_key, receiver_public_key)
            
            # Upload signature file to Supabase storage
            signature_path = f"signature-files/{sign_id}/{file.filename}.sig"
            client.storage.from_('signature-files').upload(
                signature_path,
                signature
            )
            
            # Upload encrypted file to Supabase storage
            file_path = f"encrypted-files/{file_id}/{file.filename}"
            client.storage.from_('encrypted-files').upload(
                file_path,
                encrypted_file
            )
            
            # Create signature record
            admin_client = getAdminClient()
            admin_client.table('signatures').insert({
                'sign_id': sign_id,
                'sign_path': signature_path,
                'creating_date': 'now()'
            }).execute()
            
            # Create file record
            admin_client.table('files').insert({
                'file_id': file_id,
                'file_name': file.filename,
                'file_path': file_path,
                'aes_key': encrypted_aes_key,
                'file_format': file.filename.split('.')[-1],
                'sign_id': sign_id,
                'receiver': receiver_id
            }).execute()
            
            flash('File uploaded and encrypted successfully!', 'success')
            
        except Exception as e:
            flash(f'Error processing file: {str(e)}', 'error')
            print(e)
            return redirect(request.url)
            
    return render_template('home.html')

@home_bp.route('/get-user-key', methods=['GET'])
@login_required
def get_user_key():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({'error': 'No user ID provided'}), 400
    
    try:
        client = getPublicClient()
        # Use the public view to get public keys
        result = client.schema('public').table('users').select('public_key').eq('user_id', user_id).execute()
        
        if not result.data:
            return jsonify({'error': 'User has no public key'}), 404
            
        return jsonify({'public_key': result.data[0]['public_key']})
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@home_bp.route('/get-my-keys', methods=['GET'])
@login_required
def get_my_keys():
    try:
        client = getPublicClient()
        # Get both keys from the secure table
        result = client.schema('dtf_secure_info').table('user_keys').select('*').eq('user_id', session['user']["id"]).execute()
        
        if not result.data:
            return jsonify({'error': 'No keys found'}), 404
            
        return jsonify({
            'public_key': result.data[0]['public_key'],
            'private_key': result.data[0]['private_key']
        })
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@home_bp.route('/upload-file', methods=['POST'])
@login_required
def upload_file(receiver_id):
    try:
        # First check if they are friends
        client = getPublicClient()
        friends_result = client.schema('public').table('friends').select('*').or_(
            f'user_id.eq.{session["user"]["id"]},friend_id.eq.{session["user"]["id"]}'
        ).and_(
            f'user_id.eq.{receiver_id},friend_id.eq.{receiver_id}'
        ).execute()
        
        if not friends_result.data:
            flash('You can only send files to your friends', 'error')
            return redirect(request.url)
        
        # Get receiver's public key
        key_result = client.schema('public').table('users').select('public_key').eq('user_id', receiver_id).execute()
        
        if not key_result.data:
            flash('Receiver has no valid public key', 'error')
            return redirect(request.url)
        
        receiver_public_key = key_result.data[0]['public_key']
    except Exception as e:
        flash('An error occurred', 'error')
        print(e)
        return redirect(request.url)

@home_bp.route('/generate-key-pair', methods=['POST'])
@login_required
def generate_key_pair():
    try:
        # Generate new RSA key pair
        rsa = RSA()
        private_key, public_key = rsa.generate_key()
        
        # Store the new keys
        admin_client = getAdminClient()
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # First check if user already has keys
                existing_keys = admin_client.schema('dtf_secure_info').table('user_keys').select('*').eq('user_id', session['user']["id"]).execute()
                
                if existing_keys.data:
                    # Update existing keys
                    keys_response = admin_client.schema('dtf_secure_info').table('user_keys').update({
                        'public_key': public_key,
                        'private_key': private_key
                    }).eq('user_id', session['user']["id"]).execute()
                else:
                    # Insert new keys
                    keys_response = admin_client.schema('dtf_secure_info').table('user_keys').insert({
                        'user_id': session['user']["id"],
                        'public_key': public_key,
                        'private_key': private_key
                    }).execute()
                
                # Update public_key in users table
                user_response = admin_client.schema('public').table('users').update({
                    'public_key': public_key
                }).eq('user_id', session['user']["id"]).execute()
                
                if not user_response.data:
                    raise Exception('Failed to update user public key')
                
                break
            except (Timeout, RequestException) as e:
                retry_count += 1
                if retry_count == max_retries:
                    raise Exception(f"Database operation timed out after {max_retries} attempts: {str(e)}")
                time.sleep(1)
            except Exception as e:
                raise e
        
        if not keys_response.data:
            flash('Failed to update key pair', 'error')
            return redirect(url_for('home.home'))
        
        flash('Key pair generated successfully!', 'success')
        return redirect(url_for('home.home'))
        
    except Exception as e:
        flash(f'Error generating key pair: {str(e)}', 'error')
        print(e)
        return redirect(url_for('home.home'))
