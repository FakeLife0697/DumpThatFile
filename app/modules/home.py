from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify, flash, send_file
from functools import wraps
from flask_restful import Api
from app.supabase_client import getPublicClient, getAdminClient
from app.modules.encrypt import SHA256, AES, RSA
from app.modules.login import login_required
import uuid
import os
import time
from requests.exceptions import Timeout, RequestException
import io
from datetime import datetime, timedelta, timezone

home_bp = Blueprint('home', __name__)
api = Api(home_bp)

@home_bp.route('/logout', methods = ['GET'])
@login_required
def logout():
    try:
        client = getPublicClient()
        client.auth.sign_out()
        session.clear()
        return redirect(url_for('index.index'))
    except Exception as e:
        session.clear()
        flash(f'Debug: Logout error: {str(e)}', 'warning')
        return redirect(url_for('index.index'))

@home_bp.route('/home', methods = ['GET', 'POST'])
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
        
        # Check filename for special characters
        if not all(ord(c) < 128 for c in file.filename):
            flash('Filename contains non-ASCII characters. Please rename your file using only English letters, numbers, dots, hyphens, and underscores.', 'error')
            return redirect(request.url)
        
        # Check if filename contains only allowed characters
        if not all(c.isalnum() or c in '.-_' for c in file.filename):
            flash('Filename contains special characters. Please use only letters, numbers, dots, hyphens, and underscores.', 'error')
            return redirect(request.url)
        
        # Check file size (5MB limit)
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        
        if size > 5 * 1024 * 1024:  # 5MB in bytes
            flash('File size exceeds 5MB limit', 'error')
            return redirect(request.url)
        
        # Handle expiry date
        expiry_date_str = request.form.get('expiry_date')
        if expiry_date_str:
            try:
                expiry_date = datetime.fromisoformat(expiry_date_str)
                expiry_date = expiry_date.replace(hour = 23, minute = 59, second = 59)
            except ValueError:
                flash('Invalid expiry date format', 'error')
                return redirect(request.url)
        else:
            # Default to 3 days from now at end of day
            expiry_date = datetime.now(timezone.utc).replace(hour = 23, minute = 59, second = 59) + timedelta(days = 3)
        
        try:
            # First check if they are friends
            client = getAdminClient()
            
            # Query both directions of friendship
            friends_result = client.table('friends').select('*').or_(
                f'user_id.eq.{session["user"]["id"]},friend_id.eq.{receiver_id},user_id.eq.{receiver_id},friend_id.eq.{session["user"]["id"]}'
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
            # Create temp directory if it doesn't exist
            temp_dir = os.path.join(os.path.dirname(os.path.relpath(__file__)), 'temp')
            os.makedirs(temp_dir, exist_ok = True)
            
            # Save file with original name in temp directory
            original_filename = file.filename
            original_filepath = os.path.join(temp_dir, original_filename)
            file.save(original_filepath)
            
            try:
                # Generate hash
                signature = sha256.hash(original_filepath)
                
                # Save signature to temp file
                signature_path = os.path.join(temp_dir, f"{original_filename}.sig")
                with open(signature_path, 'w') as f:
                    f.write(signature)
                
                # Generate and encrypt with AES
                aes = AES()
                aes_key, iv = aes.generate_key()
                encrypted_file_path = aes.encrypt(original_filepath, aes_key, iv)
                
                # Get just the filename for storage
                encrypted_filename = f"{original_filename}.enc"
                signature_filename = f"{original_filename}.sig"
                
                # Read encrypted file
                with open(encrypted_file_path, 'rb') as f:
                    encrypted_file = f.read()
                
                # Read signature file
                with open(signature_path, 'rb') as f:
                    signature_content = f.read()
                
                # Upload signature to Supabase storage
                signature_storage_path = f"signature-files/{sign_id}/{signature_filename}"
                signature_upload = client.storage.from_('signature-files').upload(
                    signature_storage_path,
                    signature_content
                )
                if not signature_upload:
                    raise Exception("Failed to upload signature file")
                
                # Upload encrypted file to Supabase storage
                file_path = f"encrypted-files/{file_id}/{encrypted_filename}"
                file_upload = client.storage.from_('encrypted-files').upload(
                    file_path,
                    encrypted_file
                )
                if not file_upload:
                    raise Exception("Failed to upload encrypted file")
                
                # Encrypt AES key with receiver's public key
                rsa = RSA()
                encrypted_aes_key = rsa.encrypt(aes_key, receiver_public_key)
                if not encrypted_aes_key:
                    raise Exception("Failed to encrypt AES key")
                
                # Create signature record
                creating_date = datetime.now(timezone.utc)

                signature_result = client.table('signatures').insert({
                    'sign_id': sign_id,
                    'sign_path': signature_storage_path,
                    'creating_date': creating_date.isoformat(),
                    'expiring_date': expiry_date.isoformat()
                }).execute()
                if not signature_result.data:
                    raise Exception("Failed to create signature record")
                
                # Create file record
                file_result = client.table('files').insert({
                    'file_id': file_id,
                    'file_name': original_filename,
                    'file_path': file_path,
                    'aes_key': encrypted_aes_key,
                    'file_format': original_filename.split('.')[-1],
                    'sign_id': sign_id,
                    'receiver': receiver_id,
                    'sender': session['user']['id'],
                    'creating_date': creating_date.isoformat(),
                    'expiring_date': expiry_date.isoformat()
                }).execute()
                if not file_result.data:
                    raise Exception("Failed to create file record")
                
                # Clean up temporary files
                os.remove(original_filepath)
                os.remove(signature_path)
                os.remove(encrypted_file_path)
                
                flash('File uploaded and encrypted successfully!', 'success')
                return redirect(url_for('home.home'))
                
            except Exception as e:
                # Clean up on error
                if os.path.exists(original_filepath):
                    os.remove(original_filepath)
                if os.path.exists(signature_path):
                    os.remove(signature_path)
                if os.path.exists(encrypted_file_path):
                    os.remove(encrypted_file_path)
                flash(f'Error processing file: {str(e)}', 'error')
                return redirect(request.url)
                
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return redirect(request.url)
            
    return render_template('home.html')

@home_bp.route('/search-users', methods = ['GET'])
@login_required
def search_users():
    query = request.args.get('query', '')
    if not query:
        return jsonify([])
    
    try:
        client = getPublicClient()
        if not client:
            flash('Database connection error', 'error')
            return redirect(url_for('home.home'))
        
        # Search users by username or email
        result = client.table('users').select('user_id, username, email').or_(
            f'username.ilike.%{query}%,email.ilike.%{query}%'
        ).execute()
        
        # Filter out current user from results
        filtered_data = [user for user in result.data if user['user_id'] != session['user']['id']]
        return jsonify(filtered_data)
    except Exception as e:
        flash(f'Debug: Search error: {str(e)}', 'error')
        return jsonify({'error': str(e)}), 500

@home_bp.route('/get-user-key', methods = ['GET'])
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

@home_bp.route('/get-my-keys', methods = ['GET'])
@login_required
def get_my_keys():
    try:
        client = getAdminClient()
        # Get both keys from the secure table
        result = client.schema('dtf_secure_info').table('user_keys').select('*').eq('user_id', session['user']['id']).execute()
        
        if not result.data:
            return jsonify({'error': 'No keys found'}), 404
            
        return jsonify({
            'public_key': result.data[0]['public_key'],
            'private_key': result.data[0]['private_key']
        })
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@home_bp.route('/upload-file', methods = ['POST'])
@login_required
def upload_file(receiver_id):
    try:
        # First check if they are friends
        client = getPublicClient()
        friends_result = client.table('friends').select('*').or_(
            f'(user_id.eq.{session["user"]["id"]},friend_id.eq.{receiver_id}),(user_id.eq.{receiver_id},friend_id.eq.{session["user"]["id"]})'
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

@home_bp.route('/generate-key-pair', methods = ['POST'])
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
                existing_keys = admin_client.schema('dtf_secure_info').table('user_keys').select('*').eq('user_id', session['user']['id']).execute()
                
                if existing_keys.data:
                    # Update existing keys
                    keys_response = admin_client.schema('dtf_secure_info').table('user_keys').update({
                        'public_key': public_key,
                        'private_key': private_key
                    }).eq('user_id', session['user']['id']).execute()
                else:
                    # Insert new keys
                    keys_response = admin_client.schema('dtf_secure_info').table('user_keys').insert({
                        'user_id': session['user']['id'],
                        'public_key': public_key,
                        'private_key': private_key
                    }).execute()
                # Update public_key in users table
                user_response = admin_client.schema('public').table('users').update({
                    'public_key': public_key
                }).eq('user_id', session['user']['id']).execute()
                
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
        return redirect(url_for('home.home'))

@home_bp.route('/get-received-files', methods=['GET'])
@login_required
def get_received_files():
    try:
        
        # Use admin client to bypass RLS policies
        client = getAdminClient()
        
        # First, let's try a simple query to see if there are any files
        simple_result = client.table('files').select('*').eq('receiver', session['user']['id']).execute()
        
        if not simple_result.data:
            # flash("Debug: No files found for this user", 'info')
            return jsonify([])
        
        # Now get files with sender information using a join
        result = client.table('files').select(
            'file_id, file_name, creating_date, sender, users!files_sender_fkey(username)'
        ).eq('receiver', session['user']['id']).execute()
        
        # Transform the result to make it easier to use in the frontend
        files = []
        for file in result.data:
            # Get sender info separately if join doesn't work
            sender_name = 'Unknown'
            if file.get('users') and file['users']:
                sender_name = file['users']['username']
            elif file.get('sender'):
                # If join failed, get sender info separately
                sender_result = client.table('users').select('username').eq('user_id', file['sender']).execute()
                if sender_result.data:
                    sender_name = sender_result.data[0]['username']
            
            files.append({
                'file_id': file['file_id'],
                'file_name': file['file_name'],
                'creating_date': file['creating_date'],
                'sender': {'username': sender_name}
            })
        
        return jsonify(files)
    except Exception as e:
        flash(f'Debug: Error in get_received_files: {str(e)}', 'error')
        return jsonify({'error': str(e)}), 500

@home_bp.route('/download-encrypted/<file_id>', methods=['GET'])
@login_required
def download_encrypted(file_id):
    try:
        # Use admin client to ensure we can access the file
        client = getAdminClient()
        
        # Get file info
        file_result = client.table('files').select('*').eq('file_id', file_id).eq('receiver', session['user']['id']).execute()
        
        if not file_result.data:
            flash('File not found or access denied', 'error')
            return redirect(url_for('home.home'))
            
        file_info = file_result.data[0]
        
        # Download encrypted file from storage
        encrypted_file = client.storage.from_('encrypted-files').download(file_info['file_path'])
        
        return send_file(
            io.BytesIO(encrypted_file),
            mimetype = 'application/octet-stream',
            as_attachment = True,
            download_name = f"{file_info['file_name']}.enc"
        )
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'error')
        return redirect(url_for('home.home'))

@home_bp.route('/download-signature/<file_id>', methods=['GET'])
@login_required
def download_signature(file_id):
    try:
        # Use admin client to ensure we can access the file
        client = getAdminClient()
        
        # Get file info
        file_result = client.table('files').select('*').eq('file_id', file_id).eq('receiver', session['user']['id']).execute()
        
        if not file_result.data:
            flash('File not found or access denied', 'error')
            return redirect(url_for('home.home'))
            
        file_info = file_result.data[0]

        sign_id = file_info['sign_id']
        sign_result = client.table('signatures').select('*').eq('sign_id', sign_id).execute()

        if not sign_result.data:
            flash('Signature not found', 'error')
            return redirect(url_for('home.home'))

        sign_info = sign_result.data[0]
        sign_path = sign_info['sign_path']

        signature_result = client.storage.from_('signature-files').download(sign_path)

        return send_file(
            io.BytesIO(signature_result),
            mimetype = 'application/octet-stream',
            as_attachment = True,
            download_name = f"{file_info['file_name']}.sig"
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f'Error decrypting file: {str(e)}', 'error')
        return redirect(url_for('home.home'))

@home_bp.route('/download-verify/<file_id>', methods=['GET'])
@login_required
def download_verify(file_id):
    try:
        # Use admin client to ensure we can access the file
        client = getAdminClient()
        
        # Get file info
        file_result = client.table('files').select('*').eq('file_id', file_id).eq('receiver', session['user']['id']).execute()
        
        if not file_result.data:
            flash('File not found or access denied', 'error')
            return redirect(url_for('home.home'))
            
        file_info = file_result.data[0]
        
        # Get signature
        signature_result = client.table('signatures').select('*').eq('sign_id', file_info['sign_id']).execute()
        
        if not signature_result.data:
            flash('Signature not found', 'error')
            return redirect(url_for('home.home'))
            
        signature_info = signature_result.data[0]
        
        # Download encrypted file and signature
        encrypted_file = client.storage.from_('encrypted-files').download(file_info['file_path'])
        signature_data = client.storage.from_('signature-files').download(signature_info['sign_path'])
        
        # Convert signature bytes to string
        signature_hash = signature_data.decode('utf-8')
        
        # Get user's private key
        key_result = client.schema('dtf_secure_info').table('user_keys').select('private_key').eq('user_id', session['user']['id']).execute()
        
        if not key_result.data:
            flash('Private key not found', 'error')
            return redirect(url_for('home.home'))
            
        private_key = key_result.data[0]['private_key']
        
        # Decrypt AES key with private key
        rsa = RSA()
        aes_key = rsa.decrypt(file_info['aes_key'], private_key)
        
        if not aes_key:
            flash('Failed to decrypt AES key', 'error')
            return redirect(url_for('home.home'))
        
        # Create temp directory if it doesn't exist
        temp_dir = os.path.join(os.path.dirname(os.path.relpath(__file__)), 'temp')
        os.makedirs(temp_dir, exist_ok=True)
        
        # Save encrypted file to temp location
        temp_encrypted_file = os.path.join(temp_dir, f"temp_encrypted_{file_id}.enc")
        with open(temp_encrypted_file, 'wb') as f:
            f.write(encrypted_file)
        
        try:
            # Decrypt file with AES using original method
            aes = AES()
            decrypted_file_path = aes.decrypt(temp_encrypted_file, aes_key)
            
            if not decrypted_file_path or not os.path.exists(decrypted_file_path):
                flash('Failed to decrypt file', 'error')
                return redirect(url_for('home.home'))
            
            # Verify signature using original method
            sha256 = SHA256()
            calculated_hash = sha256.hash(decrypted_file_path)
            
            if calculated_hash != signature_hash:
                flash('File integrity verification failed!', 'error')
                # Clean up temp files before returning
                if os.path.exists(temp_encrypted_file):
                    os.remove(temp_encrypted_file)
                if os.path.exists(decrypted_file_path):
                    os.remove(decrypted_file_path)
                return redirect(url_for('home.home'))
            
            # Read the decrypted file for sending
            with open(decrypted_file_path, 'rb') as f:
                decrypted_data = f.read()
            
            # Clean up temp files
            if os.path.exists(temp_encrypted_file):
                os.remove(temp_encrypted_file)
            if os.path.exists(decrypted_file_path):
                os.remove(decrypted_file_path)
            
            flash('File integrity verified successfully!', 'success')
            return send_file(
                io.BytesIO(decrypted_data),
                mimetype = 'application/octet-stream',
                as_attachment = True,
                download_name = file_info['file_name']
            )
            
        except Exception as e:
            # Clean up temp files on error
            if os.path.exists(temp_encrypted_file):
                os.remove(temp_encrypted_file)
            if 'decrypted_file_path' in locals() and os.path.exists(decrypted_file_path):
                os.remove(decrypted_file_path)
            raise e
    except Exception as e:
        import traceback
        traceback.print_exc()
        flash(f'Error processing file: {str(e)}', 'error')
        return redirect(url_for('home.home'))

@home_bp.route('/add-friend', methods=['POST'])
@login_required
def add_friend():
    try:
        data = request.get_json()
        friend_id = data.get('friend_id')
        
        if not friend_id:
            flash('No friend ID provided', 'error')
            return jsonify({'message': 'No friend ID provided', 'reload': True}), 400
            
        if friend_id == session['user']['id']:
            flash('Cannot add yourself as a friend', 'error')
            return jsonify({'message': 'Cannot add yourself as a friend', 'reload': True}), 400
            
        # Use admin client to bypass RLS for checking existing friendships
        admin_client = getAdminClient()
        if not admin_client:
            flash('Database connection error', 'error')
            return jsonify({'message': 'Database connection error', 'reload': True}), 500
        
        # Check if friendship already exists in either direction
        existing_friendship = admin_client.table('friends').select('*').or_(
            f'and(user_id.eq.{session["user"]["id"]},friend_id.eq.{friend_id}),and(user_id.eq.{friend_id},friend_id.eq.{session["user"]["id"]})'
        ).execute()
        
        if existing_friendship.data:
            flash('Friendship already exists', 'error')
            return jsonify({'message': 'Friendship already exists', 'reload': True}), 400
        
        # Add new friendship
        result = admin_client.table('friends').insert({
            'user_id': session['user']['id'],
            'friend_id': friend_id
        }).execute()
        
        if not result.data:
            flash('Failed to add friend', 'error')
            return jsonify({'message': 'Failed to add friend', 'reload': True}), 500
        
        flash('Friend added successfully', 'success')
        return jsonify({'message': 'Friend added successfully', 'reload': True})
        
    except Exception as e:
        flash(f'Error adding friend: {str(e)}', 'error')
        return jsonify({'message': f'Error adding friend: {str(e)}', 'reload': True}), 500

@home_bp.route('/get-friends', methods=['GET'])
@login_required
def get_friends():
    try:
        client = getPublicClient()
        
        # First, get all friendships where user is either user_id or friend_id
        result = client.table('friends').select(
            'user_id, friend_id'
        ).or_(
            f'user_id.eq.{session["user"]["id"]},friend_id.eq.{session["user"]["id"]}'
        ).execute()
        
        if not result.data:
            return jsonify([])
        
        friends = []
        for friendship in result.data:
            # Determine which ID is the friend's ID
            friend_id = friendship['friend_id'] if friendship['user_id'] == session['user']['id'] else friendship['user_id']
            
            # Get friend's user info
            user_result = client.table('users').select('username, email').eq('user_id', friend_id).execute()
            
            if user_result.data:
                friend_info = user_result.data[0]
                friends.append({
                    'user_id': friend_id,
                    'username': friend_info['username'],
                    'email': friend_info['email']
                })
        
        return jsonify(friends)
        
    except Exception as e:
        flash(f'Error getting friends: {str(e)}', 'error')
        return jsonify([])  # Return empty array on error
