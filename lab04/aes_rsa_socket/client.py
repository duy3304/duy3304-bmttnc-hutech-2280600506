from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading

# Tạo socket client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.settimeout(10)
try:
    client_socket.connect(('localhost', 12345))
except Exception as e:
    print(f"Failed to connect to server: {e}")
    exit(1)

# Tạo khóa RSA cho client
client_key = RSA.generate(2048)
client_socket.send(client_key.publickey().export_key(format='PEM'))

# Nhận khóa công khai từ server
try:
    raw_key = client_socket.recv(2048)
    print("Raw key received:", raw_key)
    server_public_key = RSA.import_key(raw_key)
except socket.timeout:
    print("Server did not respond within 10 seconds")
    client_socket.close()
    exit(1)
except Exception as e:
    print(f"Error receiving server key: {e}")
    client_socket.close()
    exit(1)

# Nhận và giải mã khóa AES từ server
try:
    encrypted_aes_key = client_socket.recv(2048)
    cipher_rsa = PKCS1_OAEP.new(client_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
except Exception as e:
    print(f"Error decrypting AES key: {e}")
    client_socket.close()
    exit(1)

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

# Hàm nhận tin nhắn
def receive_messages():
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print("Server disconnected")
                break
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print("Received:", decrypted_message)
        except socket.timeout:
            continue  # Bỏ qua timeout, tiếp tục chờ
        except Exception as e:
            print(f"Error receiving message: {e}")
            break

# Khởi tạo thread nhận tin nhắn
receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()

# Gửi tin nhắn
while True:
    try:
        message = input("Enter message ('exit' to quit): ")
        encrypted_message = encrypt_message(aes_key, message)
        client_socket.send(encrypted_message)
        if message == "exit":
            break
    except Exception as e:
        print(f"Error sending message: {e}")
        break

# Đóng socket
client_socket.close()
print("Client disconnected")