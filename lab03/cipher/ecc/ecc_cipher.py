import ecdsa
import os

# Đảm bảo thư mục tồn tại
if not os.path.exists('cipher/ecc/keys'):
    try:
        os.makedirs('cipher/ecc/keys', exist_ok=True)
    except Exception as e:
        print(f"Error creating directory 'cipher/ecc/keys': {str(e)}")
        raise

class ECCCipher:
    def __init__(self):
        self.private_key_path = 'cipher/ecc/keys/privateKey.pem'
        self.public_key_path = 'cipher/ecc/keys/publicKey.pem'

    def generate_keys(self):
        try:
            sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            vk = sk.verifying_key
            
            with open(self.private_key_path, 'wb') as p:
                p.write(sk.to_pem())
            
            with open(self.public_key_path, 'wb') as p:
                p.write(vk.to_pem())
            print("Keys generated successfully")
        except Exception as e:
            print(f"Error generating keys: {str(e)}")
            raise

    def load_keys(self):
        try:
            with open(self.private_key_path, 'rb') as p:
                sk = ecdsa.SigningKey.from_pem(p.read())
            
            with open(self.public_key_path, 'rb') as p:
                vk = ecdsa.VerifyingKey.from_pem(p.read())
            print(f"Loaded keys - Private key: {id(sk)}, Public key: {id(vk)}")
            return sk, vk
        except Exception as e:
            print(f"Error loading keys: {str(e)}")
            raise

    def sign(self, message, key):
        try:
            if isinstance(message, str):
                message = message.encode('ascii')
            print(f"Signing message: {message}")
            signature = key.sign(message)
            return signature
        except Exception as e:
            print(f"Error signing message: {str(e)}")
            raise

    def verify(self, message, signature, key):
        try:
            if isinstance(message, str):
                message = message.encode('ascii')
            print(f"Verifying message: {message}, Signature: {signature.hex()}")
            return key.verify(signature, message)
        except ecdsa.BadSignatureError:
            print("Verification failed: Bad signature")
            return False
        except Exception as e:
            print(f"Error verifying signature: {str(e)}")
            raise