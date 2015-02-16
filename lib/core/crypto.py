import os

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import HMAC, SHA256


class CryptoBox():

    def __init__(self):
        self.privkey = None
        self.pubkey = None
        self.peerPubkey = None
        
    def importKey(self, filename, passphrase=None):
        key = None
        if os.path.isfile(filename):
            with open(filename) as fd:
                key = RSA.importKey(fd.read(), passphrase)
        return key

    def setKey(self, filename):
        self.privkey = self.importKey(filename)
        if self.privkey is None:
            return False
        self.pubkey = self.privkey.publickey()
        if self.pubkey is None:
            return False
        return True

    def setPeerPubkey(self, filename):
        self.peerPubkey = self.importKey()
        if self.peerPubkey is None:
            return False
        else:
            return True

    def asymmetricEncrypt(self, msg):
        cipher = PKCS1_OAEP.new(self.peerPubkey)
	return cipher.encrypt(msg)

    def asymmetricDecrypt(self, msg):
        cipher = PKCS1_OAEP.new(self.privkey)
        return cipher.decrypt(msg)

    def symmetricEncrypt(self, msg, key, iv):
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.encrypt(msg)

    def symmetricDecrypt(self, msg, key, iv):
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(msg)
   
    def sign(self, msg):
       signer = PKCS1_v1_5.new(self.privkey)
       return signer.sign(SHA256.new(msg))

    def verify(self, signature):
        verifier = PKCS1_v1_5.new(self.pubkey)
        if verifier.verify(SHA256.new(msg), signature):
            return True
        else:
            return False

    def verifyHMAC(self, msg, hmac, secret):
        h = HMAC.new(secret, msg=msg, digestmod=SHA256).digest()
        if  h == hmac:
            return True
        else:
            return False
