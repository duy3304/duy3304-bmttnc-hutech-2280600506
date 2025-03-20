from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

class RSACIPHER:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        print("Generating RSA keys...")
        key = RSA.generate(2048)
        self.private_key = key
        self.public_key = key.publickey()

    def load_keys(self):
        if not self.private_key or not self.public_key:
            self.generate_keys()
        return self.private_key, self.public_key

    def encrypt(self, message, key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        cipher = PKCS1_OAEP.new(key)
        encrypted = cipher.encrypt(message)
        return encrypted

    def decrypt(self, ciphertext, key):
        cipher = PKCS1_OAEP.new(key)
        decrypted = cipher.decrypt(ciphertext)
        return decrypted.decode('utf-8')

    def sign(self, message, private_key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        print(f"Signing message (bytes): {message}")
        h = SHA256.new(message)
        signature = pkcs1_15.new(private_key).sign(h)
        return signature

    def verify(self, message, signature, public_key):
        if isinstance(message, str):
            message = message.encode('utf-8')
        print(f"Verifying message (bytes): {message}, Signature (hex): {signature.hex()}")
        h = SHA256.new(message)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError) as e:
            print(f"Verification failed with error: {str(e)}")
            return False