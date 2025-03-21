from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# Tạo socket server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)
print("Server listening on localhost:12345...")

# Tạo khóa RSA cho server
server_key = RSA.generate(2048)

# Danh sách clients (socket và khóa AES tương ứng)
clients = []

# Hàm mã hóa tin nhắn
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Hàm giải mã tin nhắn
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

# Hàm xử lý từng client
def handle_client(client_socket, client_address):
    print(f"Connected with {client_address}")

    # Gửi khóa công khai của server cho client
    client_socket.send(server_key.publickey().export_key(format='PEM'))

    # Nhận khóa công khai từ client
    try:
        client_received_key = RSA.import_key(client_socket.recv(2048))
    except Exception as e:
        print(f"Error receiving client key: {e}")
        client_socket.close()
        return

    # Tạo và mã hóa khóa AES
    aes_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(client_received_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    client_socket.send(encrypted_aes_key)

    # Thêm client vào danh sách
    clients.append((client_socket, aes_key))

    # Nhận và xử lý tin nhắn
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:  # Client ngắt kết nối
                break
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print(f"Received from {client_address}: {decrypted_message}")

            # Gửi phản hồi về client gửi tin nhắn
            response = f"Server received: {decrypted_message}"
            encrypted_response = encrypt_message(aes_key, response)
            client_socket.send(encrypted_response)

            # Gửi tin nhắn đến các client khác
            for client, key in clients:
                if client != client_socket:
                    encrypted = encrypt_message(key, decrypted_message)
                    client.send(encrypted)

            if decrypted_message == "exit":
                break
        except Exception as e:
            print(f"Error with {client_address}: {e}")
            break

    # Xóa client khỏi danh sách và đóng kết nối
    if (client_socket, aes_key) in clients:
        clients.remove((client_socket, aes_key))
    client_socket.close()
    print(f"Connection with {client_address} closed")

# Chấp nhận kết nối từ client
while True:
    try:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
        server_socket.close()
        break