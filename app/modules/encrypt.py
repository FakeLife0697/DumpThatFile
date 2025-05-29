import asyncio, base64, os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

class Encryption():
    def __init__(self):
        self._enc_type = None
        pass
    
    def __str__(self):
        return f"{self._enc_type}"
    
    def get_type(self):
        return self._enc_type

class RSA(Encryption):
    def __init__(self):
        super().__init__()
        self._enc_type = "RSA"
        self._key_size = 2048
    
    def generate_key(self):
        private_key = None
        public_key = None
        
        try:
            key = rsa.generate_private_key(public_exponent = 65537, key_size = self._key_size)
            private_key = key.private_bytes(
                encoding = serialization.Encoding.PEM,  # Encode in PEM format
                format = serialization.PrivateFormat.PKCS8,  # Use PKCS8 format
                encryption_algorithm = serialization.NoEncryption(),  # No password encryption
            ).decode('utf-8')
            
            public_key = key.public_key().public_bytes(
                encoding = serialization.Encoding.PEM,  # Encode in PEM format
                format = serialization.PublicFormat.PKCS1,  # Use PKCS1 format
            ).decode('utf-8')
            
        except Exception as e:
            print("Process failed: RSA generation")
            print(e)
            
        return private_key, public_key
            
    def encrypt(self, aes_key: str, public_key: str = None):
        cipher_aes_key = None
        try:
            if public_key:
                rsa_public_key = serialization.load_pem_public_key(
                    public_key.encode('utf-8'),
                    backend = default_backend()
                )
                
                aes_key_byte = base64.b64encode(aes_key.encode('utf-16')).decode('utf-8')
                cipher_aes_key = base64.b64encode(
                    rsa_public_key.encrypt(
                        base64.b64decode(aes_key_byte),
                        padding.OAEP(
                            mgf = padding.MGF1(algorithm = hashes.SHA256()),
                            algorithm = hashes.SHA256(),
                            label = None
                        )
                    )
                ).decode('utf-16')
        
        except Exception as e:
            print("Process failed: RSA encryption")
            print(e)

        return cipher_aes_key

    def decrypt(self, cipher_aes_key: str, private_key: str = None):
        decrypted_key = None
        try:
            if private_key:
                rsa_private_key = serialization.load_pem_private_key(
                    private_key.encode('utf-8'),
                    password = None,
                    backend = default_backend()
                )
                
                decrypted_key = rsa_private_key.decrypt(
                    base64.b64decode(base64.b64decode(base64.b64encode(cipher_aes_key.encode('utf-16')).decode('utf-8'))),
                    padding.OAEP(
                        mgf = padding.MGF1(algorithm = hashes.SHA256()),
                        algorithm = hashes.SHA256(),
                        label = None
                    )
                ).decode('utf-16')
        
        except Exception as e:
            print("Process failed: RSA decryption")
            print(e)

        return decrypted_key
    
class AES(Encryption):
    def __init__(self):
        super().__init__()
        self._enc_type = "AES"
        self.chunk_size = 64*1024 # (64KB)
        
    def generate_key(self):
        key = None
        iv = None
        
        try:
            key = base64.b64encode(os.urandom(32)).decode('utf-8')
            iv = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        except Exception as e:
            print("Process failed")
            print(e)
            
        return key, iv
    
    def encrypt(self, file, key: str = None, iv: str = None):
        cipherfile = None
        try:
            key = base64.b64decode(key.encode('utf-8'))
            iv = base64.b64decode(iv.encode('utf-8'))
            
            padder = PKCS7(algorithms.AES256.block_size).padder()
            cipher = Cipher(algorithms.AES256(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            cipherfile = f"{file}.enc"
            
            with open(file, 'rb') as fin, open(cipherfile, 'wb') as fout:
                fout.write(iv)
                
                while True:
                    plain = fin.read(self.chunk_size)
                    if len(plain) == 0:
                        break
                    
                    padded_plain = padder.update(plain)
                    ciphertext = encryptor.update(padded_plain)
                    fout.write(ciphertext)
                    
                final_pad = padder.finalize()
                final_ciphertext = encryptor.update(final_pad) + encryptor.finalize()
                fout.write(final_ciphertext)
        
        except Exception as e:
            print("Process failed")
            print(e)
        
        return cipherfile
    
    def decrypt(self, cipherfile: str = None, key: str = None):
        decrypted_file = None
        
        try:
            key = base64.b64decode(key.encode('utf-8'))
            decrypted_file = ".".join(cipherfile.split(".", )[:-1])
            
            with open(cipherfile, 'rb') as fin, open(decrypted_file, 'wb') as fout:
                iv = fin.read(16)
                unpadder = PKCS7(algorithms.AES256.block_size).unpadder()
                cipher = Cipher(algorithms.AES256(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                
                while True:
                    ciphertext = fin.read(self.chunk_size)
                    if len(ciphertext) == 0:
                        break
                    
                    decrypted_text = decryptor.update(ciphertext)
                    unpadded_text = unpadder.update(decrypted_text)
                    fout.write(unpadded_text)
                    
                final_text = decryptor.finalize()
                final_unpad = unpadder.update(final_text) + unpadder.finalize()
                fout.write(final_unpad)
        
        except Exception as e:
            print("Process failed")
            print(e)
        
        return decrypted_file

class SHA256(Encryption):
    def __init__(self):
        super().__init__()
        self._enc_type = "SHA256"
        self.chunk_size = 64*1024 # (64KB)
        
    def hash(self, file = None):
        digest = None
        try:
            hash_obj = hashes.Hash(hashes.SHA256(), backend = default_backend())
            with open(file, 'rb') as fin:
                while True:
                    plain = fin.read(self.chunk_size)
                    if len(plain) == 0:
                        break
                    
                    hash_obj.update(plain)
            
            digest = hash_obj.finalize().hex()
        
        except Exception as e:
            print("Process failed")
            print(e)
        
        return digest
        
    def compare(self, hash1 = None, hash2 = None):
        return hash1 == hash2