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
  f = open("secret.txt", "w")
  print("saving secret: ", s)
  f.write(str(s))
  f.close()

def read_secret():
  f = open("secret.txt","r")
  secret = f.readline()
  f.close()
  return str(secret)

def encrypt_secret(s,p):
  salt = os.urandom(16) 
  print(type(salt))
  #save salt
  salt_file = open("salt.txt","w")
  salt_file.write(str(salt))
  print("esalt:",str(salt))
  salt_file.close()
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000
  ) 
  key = base64.urlsafe_b64encode(kdf.derive(bytes(p,'UTF-8')))
  f = Fernet(key)
  return f.encrypt(s)

def decrypt_secret(p):
  print(p)
  salt_file = open('salt.txt', 'r')
  salt = salt_file.read()
  print("salt:",salt)
  salt_file.close()
  enc_content = read_secret()
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000
  )
  key = base64.urlsafe_b64encode(kdf.derive(bytes(p,'UTF-8')))
  f = Fernet(key)
  print("enc_content:",enc_content)
  print("conv: ", bytes(enc_content,'UTF-8'))
  return f.decrypt(bytes(enc_content,'UTF-8'))

try:
  if sys.argv[1] == '--generate-qr':
    secret = generate_secret(16)
    #encrypt secret
    password = bytes(sys.argv[3], 'UTF-8')
    enc_token = encrypt_secret(secret,password)
    print("enc_token:",enc_token)
    save_secret(enc_token.decode('UTF-8'))
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

