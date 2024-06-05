from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def generate_key():
    return Fernet.generate_key()

def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key

def encrypt_file_in_place(key, filename,salt,passphrase):
    cipher = Fernet(key)
    with open(filename, 'rb') as file:
        plaintext = file.read()
    ciphertext = cipher.encrypt(plaintext)
    with open(filename, 'wb') as file:
        key = encrypt_the_key(key,salt,passphrase)
        file.write(key)  # Write the encryption key to the file
        file.write(b'\n')
        file.write(b'\n')
        file.write(b'\n') # Add a newline for separation
        file.write(ciphertext)  # Write the encrypted content to the file
def encrypt_the_key(key):
    passphrase = "If_you_are_reading_this_then_this_is_the_key_for_the_key"
    salt = b'\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
    my_common_key = derive_key_from_passphrase(passphrase, salt)
    cipher = Fernet(my_common_key)
    encrypted_key = cipher.encrypt(key)
    print("The encrypted key: ",encrypted_key)
    print()
    return encrypted_key

def decrypt_file_in_place(filename,user_entered_key):
    passphrase = "If_you_are_reading_this_then_this_is_the_key_for_the_key"
    fixed_salt = b'\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
    custom_key = derive_key_from_passphrase(passphrase, fixed_salt)
    with open(filename, 'rb') as file:
        content = file.read()

    encrypted_key, ciphertext = content.split(b'\n\n\n', 1)

    decrypted_key = decrypt_the_key(encrypted_key, custom_key)
    if user_entered_key.strip() != str(decrypted_key.strip()):
        print("The decryption key you entered is not correct key for this file")
        print("Enter the correct one!")
        print("Good bye!!!")
        return

    cipher = Fernet(decrypted_key)
    plaintext = cipher.decrypt(ciphertext)
    with open(filename, 'wb') as file:
        file.write(plaintext)
def decrypt_the_key(encrypted_key, custom_key):
    cipher = Fernet(custom_key)
    decrypted_key = cipher.decrypt(encrypted_key)
    return decrypted_key


def send_email(sender_email, sender_password, recipient_email, filename,key):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = "Decryption Key for the File"
    message= "Hi this is the decrption mail for the file "+filename+"\n\n"+"Key: "+str(key)
    msg.attach(MIMEText(message, 'plain'))

    # Create SMTP session
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, sender_password)

    # Send the email
    text = msg.as_string()
    server.sendmail(sender_email, recipient_email, text)
    server.quit()

while(True):
    print("Enter the options:")
    print("1.Encrypt the text file")
    print("2.Decrypt the text file")
    print("3.exit")
    print("enter the option:")
    user_input =int(input())
    if user_input==1:
        key = generate_key()
        print("Enter the File path:")
        filename = input().strip()
        print("the original key:",key)
        print("Enter the valid Email address:")
        recipient_email= input().strip()
        send_email("waterresq@gmail.com","waterresq@2023", recipient_email,filename,key)
        print("The Encryption key has been sent to the email.")
        encrypt_file_in_place(key, filename,salt,passphrase)
        print("File encrypted and saved successfully.\n")
    elif user_input==2:
        print("Enter the File path:")
        filename= input().strip()
        print("Enter the Decryption key")
        user_entered_key = input().strip()
        decrypt_file_in_place(filename, passphrase, salt,user_entered_key)
        print("File decrypted and saved successfully.\n")
    else:
        print("You selected to exit. BYE BYE!\n")