from gevent import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import HMAC, SHA256
from Crypto import Random


def process_orders(sock):
    key = RSA.importKey(open('private.pem').read())
    cipher = PKCS1_OAEP.new(key)
    msg = sock.recv(1024)
    payload = cipher.decrypt(msg)
    key = payload[:16]
    iv = payload[16:32]
    secret = payload[32:64]
    print key.encode('hex')
    print iv.encode('hex')
    print secret.encode('hex')
    hmac = HMAC.new(secret, msg='Attack at dawn', digestmod=SHA256).digest()
    print hmac.encode('hex')
    privkey = RSA.importKey(open('private.pem').read())
    signer = PKCS1_v1_5.new(privkey)
    h = SHA256.new('Attack at dawn')
    signature = signer.sign(h)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    msg = cipher.encrypt(signature+hmac+'Attack at dawn')
    sock.sendall(msg)
    sock.close()
 

socket = socket.socket()
socket.connect(('127.0.0.1', 8000))
process_orders(socket)
