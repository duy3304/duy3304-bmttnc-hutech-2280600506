from flask import Flask, request, jsonify
from cipher.rsa import RSACIPHER
from cipher.ecc import ECCCipher


app = Flask(__name__)
rsa_cipher = RSACIPHER()


@app.route('/api/rsa/generate_keys', methods=['GET'])
def rsa_generate_keys():
    rsa_cipher.generate_keys()
    private_key, public_key = rsa_cipher.load_keys()
    print(f"Generated keys - Private key object: {id(private_key)}, Public key object: {id(public_key)}")
    return jsonify({'message': 'Keys generated successfully'})

@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.json 
    message = data['message']
    key_type = data['key_type']
    private_key, public_key = rsa_cipher.load_keys()
    print(f"Encrypt - Using key: {id(public_key) if key_type == 'public' else id(private_key)}")
    if key_type == 'public':
        key = public_key
    elif key_type == 'private':
        key = private_key
    else:
        return jsonify({'error': 'Invalid key type'})
    try:
        encrypted_message = rsa_cipher.encrypt(message, key)
        encrypted_hex = encrypted_message.hex()
        return jsonify({'encrypted_message': encrypted_hex})
    except ValueError as e:
        return jsonify({'error': str(e)})

@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.json 
    ciphertext_hex = data['ciphertext']
    key_type = data['key_type']
    private_key, public_key = rsa_cipher.load_keys()
    print(f"Decrypt - Using key: {id(private_key) if key_type == 'private' else id(public_key)}")
    if key_type == 'public':
        key = public_key
    elif key_type == 'private':
        key = private_key
    else:
        return jsonify({'error': 'Invalid key type'})
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
        decrypted_message = rsa_cipher.decrypt(ciphertext, key)
        return jsonify({'decrypted_message': decrypted_message})
    except ValueError as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'})

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign_message():
    data = request.json 
    message = data['message']
    private_key, _ = rsa_cipher.load_keys()
    print(f"Signing - Message: {message}, Using private key: {id(private_key)}")
    try:
        signature = rsa_cipher.sign(message, private_key)
        signature_hex = signature.hex()
        print(f"Signature generated: {signature_hex}")
        return jsonify({'signature': signature_hex})
    except ValueError as e:
        return jsonify({'error': str(e)})

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify_signature():
    data = request.json 
    message = data['message']
    signature_hex = data['signature']
    public_key, _ = rsa_cipher.load_keys()
    print(f"Verifying - Message: {message}, Signature: {signature_hex}, Using public key: {id(public_key)}")
    try:
        signature = bytes.fromhex(signature_hex)
        is_verified = rsa_cipher.verify(message, signature, public_key)
        print(f"Verification result: {is_verified}")
        return jsonify({'is_verified': is_verified})
    except ValueError as e:
        return jsonify({'error': f'Verification failed: {str(e)}'})
    
    
#ecc
ecc_cipher = ECCCipher()

@app.route('/api/ecc/generate_keys', methods=['GET'])
def ecc_generate_keys():
    ecc_cipher.generate_keys()
    return jsonify({'message': 'Key generated successfully'})

@app.route('/api/ecc/sign', methods=['POST'])
def ecc_sign_message():
    data = request.json
    message = data['message']
    private_key, _ = ecc_cipher.load_keys()
    signature = ecc_cipher.sign(message, private_key)
    signature_hex = signature.hex()
    return jsonify({'signature': signature_hex})

@app.route('/api/ecc/verify', methods=['POST'])
def ecc_verify_signature():
    data = request.json 
    message = data['message']
    signature_hex = data['signature']
    _, public_key = ecc_cipher.load_keys()  # Sửa: Lấy public_key (vk) thay vì private_key (sk)
    signature = bytes.fromhex(signature_hex)
    is_verified = ecc_cipher.verify(message, signature, public_key)
    return jsonify({'is_verified': is_verified})



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)