from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import tkinter as tk
from tkinter import messagebox, filedialog
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

def encrypt_file_in_place(key, filename):
    passphrase = "If_you_are_reading_this_then_this_is_the_key_for_the_key"
    salt = b'\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10'
    cipher = Fernet(key)
    with open(filename, 'rb') as file:
        plaintext = file.read()
    ciphertext = cipher.encrypt(plaintext)
    with open(filename, 'wb') as file:
        key = encrypt_the_key(key)
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
    print(content)
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

def browse_file(label):
    filename = filedialog.askopenfilename()
    label.config(text=filename)
    return filename


def encrypt():
    key = generate_key()
    filename = os.path.normpath(file_path.cget("text"))  # Normalize the file path
    recipient_email = recipient_email_entry.get()
    # send_email("your_email@gmail.com", "your_password", recipient_email, filename, key)
    # messagebox.showinfo("Success", "File encrypted and key sent to email successfully.")
    print(filename,key)
    encrypt_file_in_place(key, filename)
    messagebox.showinfo("Success", "File encrypted and saved successfully.")
def decrypt():
    filename = file_path.cget("text")
    key = key_entry.get()
    decrypt_file_in_place(filename, key)
    messagebox.showinfo("Success", "File decrypted and saved successfully.")
root = tk.Tk()
root.title("File Encryption Tool")

frame = tk.Frame(root)
frame.pack(padx=100, pady=100)

# Load the image
image = tk.PhotoImage(file='images/image.png')  # Replace "image.png" with the path to your image file

# Create a label to display the image
image_label = tk.Label(frame, image=image)
image_label.grid(row=0, column=0, columnspan=3, padx=5, pady=5)

file_label = tk.Label(frame, text="Select a file:")
file_label.grid(row=1, column=0, padx=5, pady=5)

file_path = tk.Label(frame, text="")
file_path.grid(row=1, column=1, padx=5, pady=5)

browse_button = tk.Button(frame, text="Browse", command=lambda: browse_file(file_path))
browse_button.grid(row=1, column=2, padx=5, pady=5)

recipient_email_label = tk.Label(frame, text="Enter the Email to send the Key:")
recipient_email_label.grid(row=2, column=0, padx=5, pady=5)

recipient_email_entry = tk.Entry(frame)
recipient_email_entry.grid(row=2, column=1, padx=5, pady=5)

encrypt_button = tk.Button(frame, text="Encrypt File", command=encrypt)
encrypt_button.grid(row=3, column=0, padx=5, pady=5)

key_label = tk.Label(frame, text="Decryption Key:")
key_label.grid(row=4, column=0, padx=5, pady=5)

key_entry = tk.Entry(frame)
key_entry.grid(row=4, column=1, padx=5, pady=5)

decrypt_button = tk.Button(frame, text="Decrypt File", command=decrypt)
decrypt_button.grid(row=5, column=0, padx=5, pady=5)

root.mainloop()

#
# while(True):
#     print("Enter the options:")
#     print("1.Encrypt the text file")
#     print("2.Decrypt the text file")
#     print("3.exit")
#     print("enter the option:")
#     user_input =int(input())
#     if user_input==1:
#         key = generate_key()
#         print("Enter the File path:")
#         filename = input().strip()
#         print("the original key:",key)
#         print("Enter the valid Email address:")
#         recipient_email= input().strip()
#         # send_email("waterresq@gmail.com","waterresq@2023", recipient_email,filename,key)
#         print("The Encryption key has been sent to the email.")
#         encrypt_file_in_place(key, filename)
#         print("File encrypted and saved successfully.\n")
#     elif user_input==2:
#         print("Enter the File path:")
#         filename= input().strip()
#         print("Enter the Decryption key")
#         user_entered_key = input().strip()
#         decrypt_file_in_place(filename,user_entered_key)
#         print("File decrypted and saved successfully.\n")
#     else:
#         print("You selected to exit. BYE BYE!\n")