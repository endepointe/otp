

# Password encrypted TOTP

## Steps

- Run the following command to genereate an encrypted qr code:   
    
    [py | python] totp.py --generate-qr -p <password>


- Run the following command to dencrypt secret and get a OTP:   
    
    [py | python] totp.py --get-otp -p <password>

