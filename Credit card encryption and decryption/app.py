from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
from os import urandom

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Used for session management and flashing messages

# Constants
KEY_SIZE = 32  # AES-256 requires a key size of 32 bytes
IV_SIZE = 16  # AES block size
SALT_SIZE = 16
ITERATIONS = 100000

# Generate a random salt
def generate_salt():
    return urandom(SALT_SIZE)

# Derive a key from a password and salt
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a credit card number
def encrypt_credit_card(credit_card_number, password):
    salt = generate_salt()
    key = derive_key(password, salt)
    iv = urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(credit_card_number.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    encoded_encrypted_data = urlsafe_b64encode(salt + iv + encrypted_data).decode()
    return encoded_encrypted_data

# Decrypt an encrypted credit card number
def decrypt_credit_card(encrypted_data, password):
    decoded_data = urlsafe_b64decode(encrypted_data.encode())
    salt = decoded_data[:SALT_SIZE]
    iv = decoded_data[SALT_SIZE:SALT_SIZE + IV_SIZE]
    encrypted_data = decoded_data[SALT_SIZE + IV_SIZE:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        credit_card_number = request.form.get('credit_card_number')
        password = request.form.get('password')
        encrypted_data = encrypt_credit_card(credit_card_number, password)
        flash(f'Encrypted Credit Card: {encrypted_data}')
        return redirect(url_for('encrypt'))
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        encrypted_data = request.form.get('encrypted_data')
        password = request.form.get('password')
        try:
            decrypted_data = decrypt_credit_card(encrypted_data, password)
            flash(f'Decrypted Credit Card: {decrypted_data}')
        except Exception:
            flash('Decryption failed. Please check the encrypted data and password.')
        return redirect(url_for('decrypt'))
    return render_template('decrypt.html')

if __name__ == '__main__':
    app.run(debug=True)
