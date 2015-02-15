from Crypto.PublicKey import RSA

key = RSA.generate(1024)
with open('private.pem','w') as fd:
 fd.write(key.exportKey(format='PEM'))
with open('public.pem','w') as fd:
 fd.write(key.publickey().exportKey(format='PEM'))
