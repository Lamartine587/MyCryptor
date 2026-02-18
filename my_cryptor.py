import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class MyCryptor:
    def __init__(self, master_password):
        """
        Initialize the encryptor with a master password.
        In a real app, you would read the salt from a file so it stays consistent.
        For this demo, we generate a new salt every time (meaning you'd strictly
        need to save the salt alongside the encrypted data to decrypt it later).
        """
        self.salt = os.urandom(16)
        self.key = self._derive_key(master_password, self.salt)
        self.fernet = Fernet(self.key)

    def _derive_key(self, password, salt):
        """
        Derives a URL-safe base64-encoded 32-byte key from the master password.
        This ensures even a simple password becomes a strong encryption key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt(self, plain_text):
        """Encrypts a plain text string."""
        return self.fernet.encrypt(plain_text.encode())

    def decrypt(self, encrypted_token):
        """Decrypts the token back to plain text."""
        return self.fernet.decrypt(encrypted_token).decode()


# --- Execution Flow ---
if __name__ == "__main__":
    # 1. Ask user for their Master Password
    mp = input("Enter your Master Password: ")

    # 2. Initialize MyCryptor
    my_cryptor = MyCryptor(mp)

    print("-" * 30)

    # 3. Simulate storing a password
    service = "Facebook"
    password_to_store = "MySecretPass123!"

    encrypted_data = my_cryptor.encrypt(password_to_store)
    print(f"Storing credentials for {service}...")
    print(f"Encrypted (What goes in the file): {encrypted_data}")

    # 4. Simulate retrieving a password
    decrypted_data = my_cryptor.decrypt(encrypted_data)
    print(f"Decrypted (What you see): {decrypted_data}")

    print("-" * 30)
    print(f"Salt used (Save this to decrypt later!): {my_cryptor.salt.hex()}")