from flask import Blueprint, render_template, session, redirect, url_for, request, jsonify, flash
from app.modules.login import is_admin
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
            return redirect(url_for('login.login'))
        if not is_admin(session['user'].id):
            return redirect(url_for('home.home'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
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
            # Get receiver's public key
            client = getPublicClient()
            key_result = client.table('user_public_keys').select('public_key').eq('user_id', receiver_id).execute()
            
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
            return redirect(request.url)
            
    return render_template('admin.html')