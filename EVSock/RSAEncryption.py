import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


class RSASimaple(object):

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_key(self, length = 1024):
        rsa_key_pair = RSA.generate(length)
        self.public_key = rsa_key_pair.publickey().export_key()
        self.private_key = rsa_key_pair.export_key()
    
    def set_public_key(self, public_key):
        self.public_key = "-----BEGIN PUBLIC KEY-----\n"
        self.public_key += public_key + "\n"
        self.public_key += "-----END PUBLIC KEY-----"
        self.public_key = self.public_key.encode("utf-8")
        
    def set_private_key(self,private_key):
        self.private_key = "-----BEGIN PRIVATE KEY-----\n"
        self.private_key += private_key + "\n"
        self.private_key += "-----END PRIVATE KEY-----"
        self.private_key = self.private_key.encode("utf-8")
        
    def encrypt(self, plaintext):
        rsa_pubkey = RSA.import_key(self.public_key)
        
        cipher_pub = PKCS1_OAEP.new(rsa_pubkey)
        print(cipher_pub)
        encrypt_data = base64.b64encode(cipher_pub.encrypt(plaintext.encode("utf-8")))
        return encrypt_data.decode(encoding="utf-8")

    def decrypt(self, crypto_message):
        rsa_private_key = RSA.import_key(self.private_key)
        cipher_private_key = PKCS1_OAEP.new(rsa_private_key)
        decrypt_data = cipher_private_key.decrypt(base64.b64decode(crypto_message))
        return decrypt_data.decode("utf-8")


if __name__ == '__main__':
    a = RSASimaple()
    a.generate_key()
    message = "hello world"
    mid = a.encrypt(message)
    print(mid)
    print(a.decrypt(mid))
