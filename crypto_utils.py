import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import tcp_by_size


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pem_public

def load_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)

def rsa_encrypt(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def generate_aes_key():
    return os.urandom(32)

# הצפנה AES-
def aes_encrypt(key, plaintext):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

# פענוח
def aes_decrypt(key, data):
    if len(data) < 28:
        raise ValueError("Encrypted data is too short")
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def send_msg(sock, msg):
    tcp_by_size.send_with_size(sock, msg)

def recv_msg(sock):
    return tcp_by_size.recv_by_size(sock)

# handshake - צד שרת
def perform_server_handshake(server_socket):
    private_key, pem_public = generate_rsa_keypair()
    send_msg(server_socket, pem_public)
    
    encrypted_aes_key = recv_msg(server_socket)
    if not encrypted_aes_key:
        raise ConnectionError("No AES key received from Proxy")
        
    aes_key = rsa_decrypt(private_key, encrypted_aes_key)
    return aes_key

# handshake - צד לקוח
def perform_client_handshake(proxy_socket):
    pem_public = recv_msg(proxy_socket)
    if not pem_public:
        raise ConnectionError("No Public Key received from Backend")
    public_key = load_public_key(pem_public)
    
    aes_key = generate_aes_key()
    encrypted_aes_key = rsa_encrypt(public_key, aes_key)
    
    send_msg(proxy_socket, encrypted_aes_key)
    return aes_key
