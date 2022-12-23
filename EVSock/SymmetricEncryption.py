import os
from Crypto.Cipher import AES
import base64


# 负责对称加密相关功能

# class AESSimple(object):

#     def __init__(self, length=128):

#         if length == 128:
#             self.iv = os.urandom(16)
#             self.random_len = 16
#         elif length == 256:
#             self.iv = os.urandom(32)
#             self.random_len = 32
#         elif length == 192:
#             self.iv = os.urandom(24)
#             self.random_len = 24
#         else:
#             raise ValueError("length in [129,192,256]")

#         random_bytes = os.urandom(self.random_len)
#         self.key = base64.b64encode(random_bytes).decode(encoding="utf-8")

#     def generate_key(self):
#         random_bytes = os.urandom(self.random_len)
#         self.key = base64.b64encode(random_bytes).decode(encoding="utf-8")
#         return self.key

#     def get_key(self):
#         return self.key

#     def get_iv(self):
#         return self.iv

#     def encrypt(self, plaintext):
#         secret_key = base64.b64decode(self.key)
#         aes_cipher = AES.new(secret_key, AES.MODE_GCM, self.iv)
#         ciphertext, auth_tag = aes_cipher.encrypt_and_digest(plaintext.encode(encoding="utf-8"))
#         return base64.b64encode(ciphertext).decode(encoding="utf-8"), auth_tag

#     def decrypt(self, encrypted, nonce, auth_tag, key):
#         ciphertext = base64.b64decode(encrypted.encode(encoding="utf-8"))
#         aes_cipher = AES.new(base64.b64decode(key), AES.MODE_GCM, nonce)
#         return aes_cipher.decrypt_and_verify(ciphertext, auth_tag).decode(encoding="utf-8")


# if __name__ == '__main__':
#     a = AESSimple(192)
#     a.generate_key()
#     n, tag = a.encrypt("hello world")
#     print(n)
#     print(a.decrypt(n, a.get_iv(), tag))

class AESSimple(object):

    def __init__(self, length=128):

        if length == 128:
            self.iv = os.urandom(16)
            self.random_len = 16
        elif length == 256:
            self.iv = os.urandom(32)
            self.random_len = 32
        elif length == 192:
            self.iv = os.urandom(24)
            self.random_len = 24
        else:
            raise ValueError("length in [129,192,256]")

        random_bytes = os.urandom(self.random_len)
        self.key = base64.b64encode(random_bytes).decode(encoding="utf-8")

    def generate_key(self):
        random_bytes = os.urandom(self.random_len)
        self.key = base64.b64encode(random_bytes).decode(encoding="utf-8")
        return self.key

    def get_key(self):
        return self.key
        
    def set_key(self,key):
        self.key = key    

    def get_iv(self):
        return self.iv

    def encrypt(self, plaintext):
        secret_key = base64.b64decode(self.key)
        aes_cipher = AES.new(secret_key, AES.MODE_GCM, self.iv)
        if type(plaintext) == str:
            ciphertext, auth_tag = aes_cipher.encrypt_and_digest(plaintext.encode(encoding="utf-8"))
        else:   # type == bytes
            ciphertext, auth_tag = aes_cipher.encrypt_and_digest(plaintext)
        return base64.b64encode(ciphertext), auth_tag

    def decrypt(self, encrypted, nonce, auth_tag):
        ciphertext = base64.b64decode(encrypted)
        aes_cipher = AES.new(base64.b64decode(self.key), AES.MODE_GCM, nonce)
        type_data = aes_cipher.decrypt_and_verify(ciphertext, auth_tag)
        return type_data

if __name__ == '__main__':
    a = AESSimple(192)
    a.generate_key()
    import pickle
    n, tag = a.encrypt(pickle.dumps("hello world"))
    print(n)
    print(pickle.loads(a.decrypt(n, a.get_iv(), tag)))