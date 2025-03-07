class VigenereCipher:
    def __init__(self):
        pass

    def vigenere_encrypt(self, text, key):
        result = ""
        key_index = 0
        for char in text:
            if char.isalpha():
                key_shift = ord(key[key_index % len(key)].upper()) - ord('A')  # Thêm thụt lề
                if char.islower():
                    result += chr((ord(char) - ord('a') + key_shift) % 26 + ord('a'))
                elif char.isupper():
                    result += chr((ord(char) - ord('A') + key_shift) % 26 + ord('A'))
                key_index += 1
            else:
                result += char
        return result

    def vigenere_decrypt(self, text, key):
        result = ""
        key_index = 0
        for char in text:
            if char.isalpha():
                key_shift = -(ord(key[key_index % len(key)].upper()) - ord('A'))  # Thêm thụt lề
                if char.islower():
                    result += chr((ord(char) - ord('a') + key_shift) % 26 + ord('a'))
                elif char.isupper():
                    result += chr((ord(char) - ord('A') + key_shift) % 26 + ord('A'))
                key_index += 1
            else:
                result += char
        return result