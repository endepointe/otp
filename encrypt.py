'''
python encrypt.py <filename> <password>
'''
import sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = bytes(sys.argv[2], 'UTF-8') 
salt = os.urandom(16)

# save the salt in a retrievable location
salt_file = open("salt.txt","w")
salt_file.write(str(salt))
salt_file.close()

kdf = PBKDF2HMAC(
  algorithm=hashes.SHA256(),
  length=32,
  salt=salt,
  iteration=390000,
)

key = base64.urlsafe_b64encode(kdf.derive(password))

f = Fernet(key)

infile = open(str(sys.argv[1]), "r")
content = infile.read()
infile.close()
print('secret:',content)

enc_token = f.encrypt(bytes(content, 'UTF-8'))
print('encrypted secret',enc_token)
outfile = open("secret.txt", "w")
outfile.write(enc_token.decode('UTF-8'))
outfile.close()

#dec_token = f.decrypt(enc_token)
#print('decrypted secret:',dec_token.decode('UTF-8'))
