'''
CS370
TOTP
Alvin Johns

# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# https://cryptography.io/en/latest/fernet/
# segno.readthedocs.io/en/stable/comparison-qrcode-libs.html
# otpauth://type/label?parameters
# otpauth://totp/Example:alice@google.com?secret=<sk_key>&issuer=Example
'''

import sys
import segno
import random
import string
import time
import math
import hmac
import hashlib
import base64
import struct
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

GENQR = False
GETOTP = False

# create hmac-sha1 signature
def hotp(secret,intervals_no):
  key = base64.b32decode(secret, False)
  msg = struct.pack(">Q", intervals_no)
  h = hmac.new(key,msg,hashlib.sha1).digest()
  o = o = h[19] & 15
  h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
  return h

def totp(secret):
  x = str(hotp(secret, intervals_no=int(time.time())//30))
  if len(x) < 6:
    while len(x) < 6:
      x = str(hotp(secret, intervals_no=int(time.time())//30))
  return x

def generate_secret(size):
  sk = ''.join([random.choice(string.ascii_uppercase) for n in range(size)])
  return str(sk)

def save_secret(s):
  f = open("secret.txt", "wb")
  print("saving secret: ", s)
  f.write(s)
  f.close()

def read_secret():
  f = open("secret.txt","rb")
  secret = f.read()
  f.close()
  return secret

def encrypt_secret(s,p):
  salt = os.urandom(16) 
  #save salt
  salt_file = open("salt.txt","wb")
  salt_file.write(salt)
  salt_file.close()
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000
  ) 
  key = base64.urlsafe_b64encode(kdf.derive(p))
  f = Fernet(key)
  print('enc salt: ',salt)
  return f.encrypt(s)

def decrypt_secret(p):
  print(p)
  salt_file = open('salt.txt', 'rb')
  salt = salt_file.read()
  salt_file.close()
  enc_content = read_secret()
  print("dec salt: ", salt)
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000
  )
  key = base64.urlsafe_b64encode(kdf.derive(p))
  f = Fernet(key)
  print("enc_content:",enc_content)
  dec_content = f.decrypt(enc_content)
  return dec_content

try:
  if sys.argv[1] == '--generate-qr':
    secret = generate_secret(16)
    #encrypt secret
    password = bytes(sys.argv[3], 'UTF-8')
    enc_token = encrypt_secret(bytes(secret,'UTF-8'),password)
    print("enc_token:",bytes(enc_token.decode('UTF-8'),'UTF-8'))
    save_secret(enc_token)
    msg_uri = "otpauth://totp/Example:johnsal@oregonstate.edu?secret="
    msg_uri += secret
    msg_uri += "&issuer=Example"
    qrcode = segno.make(msg_uri)
    qrcode.save("otp.svg",scale=10)
    print("QR code generated at otp.svg")
    exit(0)
  elif sys.argv[1] == '--get-otp':
    password = bytes(sys.argv[3], 'UTF-8') 
    while True:
      print("Code valid for 30 seconds:",totp(decrypt_secret(password)))
      time.sleep(30)
except (IndexError):
  print("Valid parameters: [--generate-qr, --get-otp]") 
except (KeyboardInterrupt):
  print("\nQuiting...")
  exit(0)

