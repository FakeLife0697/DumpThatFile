from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.PublicKey import ElGamal
from Crypto import Random
import os

class DiffieHellman:
    def __init__(self):
        self._enc_type = "DiffieHellman"
        pass
    
    def generate_key(self):
        parameters = dh.generate_parameters(generator = 2, key_size = 2048, backend = default_backend())
        user1_private_key = parameters.generate_private_key()
        user2_private_key = parameters.generate_private_key()
        shared_key = user1_private_key.exchange(user2_private_key.public_key())
        derived_key = HKDF(algorithm = hashes.SHA256(), length = 32, salt = None, info = b'handshake data').derive(shared_key)
        
        pass
    
    def encrypt():
        pass
    
    def decrypt():
        pass
    
class EG:
    def __init__(self):
        self._enc_type = "ElGamal"
        pass
    
    def generate_key(self):
        key = ElGamal.generate(2048, Random.new())
        pass
    
    def encrypt(key):
        pass
    
    def decrypt():
        pass
        