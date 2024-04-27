import sys
import os
from string import punctuation, ascii_uppercase, ascii_lowercase, digits
from random import choices, shuffle
from cryptography.fernet import Fernet
from getpass import getpass

VAULT_PASSPHRASE_LENGTH = 10
PWD_LENGTH: int = 30


def get_user_input():
    while True:
        registration_app = input('(e.g. Gmail) Where are you registering: ').strip()
        if registration_app != '':
            break

    final_password = registration_app.replace(' ', '_') + autogen_passphrase()
    username = input("(Can be escaped)Username: ").strip()
    notes = input('(Can be escaped)Notes: ').strip()
    notes = "None" if notes == "" else notes
    return registration_app, final_password, username, notes


def autogen_passphrase(pwd_length: int = PWD_LENGTH):
    # At least 10; must be the multiple of 5
    if pwd_length % 5 != 0 or pwd_length < 10:
        raise ValueError("Password length must be: At least 10 and A multiple of 5.")

    PUNC = punctuation
    UPPER_LETTERS = ascii_uppercase
    LOWER_LETTERS = ascii_lowercase
    DIG = digits

    PUNC_NUMBER = int(pwd_length * 0.2)
    UPPER_LETTERS_NUMBER = int(pwd_length * 0.2)
    LOWER_LETTERS_NUMBER = int(pwd_length * 0.2)
    DIGITS_NUMBER = int(pwd_length - PUNC_NUMBER - UPPER_LETTERS_NUMBER - LOWER_LETTERS_NUMBER)

    special_chars = choices(PUNC, k=PUNC_NUMBER)
    random_upper_letters = choices(UPPER_LETTERS, k=UPPER_LETTERS_NUMBER)
    random_lower_letters = choices(LOWER_LETTERS, k=LOWER_LETTERS_NUMBER)
    random_digits = choices(DIG, k=DIGITS_NUMBER)

    chars_list = special_chars + random_upper_letters + random_lower_letters + random_digits
    shuffle(chars_list)
    password = ''.join(chars_list)
    return password


class PasswordVault:

    def __init__(self):
        self._file_vault_name = 'password_vault_encrypted.txt'
        _is_vault_exist: bool = self.check_vault_existence()

        if _is_vault_exist:
            self._vault_passphrase = self.ask_vault_passphrase()
            self._vault_fernet_key = self.passphrase_convert_to_fernet_key()
            self.fernet = Fernet(key=self._vault_fernet_key)
        else:
            self.create_new_vault()

        self._vault_data = self.decrypt_file()

    def passphrase_convert_to_fernet_key(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend
        from base64 import urlsafe_b64encode

        salt = b'autogen_complex_pwd'

        # Use PBKDF2HMAC to derive a key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        # Derive the key using your passphrase
        key = kdf.derive(self._vault_passphrase.encode())

        # Convert the derived key into a Fernet key
        fernet_key = urlsafe_b64encode(key)

        return fernet_key

    @classmethod
    def ask_vault_passphrase(self) -> str:
        return getpass('Vault Pass: ')

    def check_vault_existence(self):
        file_path = os.path.join(os.getcwd(), self._file_vault_name)
        return True if os.path.exists(file_path) else False

    def create_new_vault(self):
        NEW_KEY = autogen_passphrase(VAULT_PASSPHRASE_LENGTH)
        self._vault_passphrase = NEW_KEY
        self._vault_fernet_key = self.passphrase_convert_to_fernet_key()
        self.fernet = Fernet(self._vault_fernet_key)

        print("You have not created a password vault yet;")
        print(f"This is your Key for pswd vault: {NEW_KEY}  ")
        print("(please store it in a safe place, like on a paper, or all your login info will be lost.")
        while True:
            confirm_key = getpass("Confirm Password: ")
            if NEW_KEY == confirm_key:
                # Update password
                self._vault_passphrase = NEW_KEY

                with open(self._file_vault_name, 'wb') as f:
                    f.write(self.fernet.encrypt(''.encode()))
                break
            else:
                continue

    def decrypt_file(self):
        with open(self._file_vault_name, 'rb') as f:
            data = f.read()
            decrypted_data = self.fernet.decrypt(data).decode()
            return decrypted_data

    def encrypt_file(self):
        with open(self._file_vault_name, 'wb') as f:
            encrypted_data = self.fernet.encrypt(self._vault_data.encode())
            f.write(encrypted_data)

    def return_login_info_by_search(self):
        if self._vault_data != '':
            retrieve_from = input("Retrieve login info from(e.g. gmail): ").lower()

            vault_data_list = self._vault_data.split('\n')
            info_containing_this_string = dict()
            for index, item in enumerate(vault_data_list, start=1):
                if retrieve_from in item.lower():
                    info_containing_this_string[index] = item

            # Present result contents to the user
            if len(info_containing_this_string) > 0:
                print(f"Found {len(info_containing_this_string)} Results:")
                for i, item in enumerate(info_containing_this_string.values(), start=1):
                    print(i, item)
            else:
                print("No Corresponding Info Found. Try Another Keyword.")

    def update_vault(self):
        decrypted_data = self.decrypt_file()
        registration_app, final_password, username, notes = get_user_input()
        content = f"APP - {registration_app}  USER - {username}  PWD - {final_password}  Notes - {notes}\n"
        decrypted_data = decrypted_data + content

        # Update the internal cache of the vault data
        self._vault_data = decrypted_data

        # Encrypt and rewrite the vault file
        self.encrypt_file()


def main():
    vault = PasswordVault()
    vault.update_vault()
    print("Login Info Updated to Your Password Vault Successfully.")


if __name__ == '__main__':
    main()
