from gevent.server import StreamServer
from gevent import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import HMAC, SHA256
from Crypto import Random


def connection_handler(sock, address):    
    try:
	key = RSA.importKey(open('public.pem').read())
	cipher = PKCS1_OAEP.new(key)
	msg = Random.new().read(64)
	enc = cipher.encrypt(msg)
        key = msg[:16]
        iv = msg[16:32]
        secret = msg[32:64]
        print key.encode('hex')
        print iv.encode('hex')
        print secret.encode('hex')
        sock.sendall(enc)
        recv = sock.recv(1024)
    except:
        pass
    finally:
        cipher = AES.new(key, AES.MODE_CFB, iv)
        msg = cipher.decrypt(recv)
        sig = msg[:128]
        hmac = msg[128:128+32]
        msg = msg[128+32:]
        pubkey = RSA.importKey(open('public.pem').read())
        print 'MSG: '+msg
        h = SHA256.new(msg)
        verifier = PKCS1_v1_5.new(pubkey)
	if verifier.verify(h, sig):
	    print "The signature is authentic."
	else:
	    print "The signature is not authentic."
        hmac2 = HMAC.new(secret, msg=msg, digestmod=SHA256).digest()
        if (hmac2 == hmac): print 'ok'
        else: print 'No'
        sock.close()


if __name__ == '__main__':
    server = StreamServer(('0.0.0.0', 8000), connection_handler)
    server.serve_forever()
