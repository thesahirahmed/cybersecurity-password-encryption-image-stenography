import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import numpy as np
from PIL import Image
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

class AESCipher:
    def __init__(self, key):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, plain_text):
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text.encode())
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        padding_needed = self.block_size - len(plain_text) % self.block_size
        padding_char = chr(padding_needed)
        return plain_text + padding_char * padding_needed

    @staticmethod
    def __unpad(plain_text):
        last_character = plain_text[-1]
        return plain_text[:-ord(last_character)]

def toBinary(data):
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, (bytes, np.ndarray)):
        return [format(i, "08b") for i in data]
    elif isinstance(data, (int, np.uint8)):
        return format(data, "08b")
    else:
        raise TypeError("Unsupported input type")

def encode_image(image_path, password, aes_cipher):
    try:
        img = Image.open(image_path).convert("RGB")
        encrypted_password = aes_cipher.encrypt(password) + "$$$"
        password_bin = toBinary(encrypted_password)
        password_bin_length = len(password_bin)

        width, height = img.size
        password_bin_index = 0
        for x in range(width):
            for y in range(height):
                if password_bin_index >= password_bin_length:
                    return img

                r, g, b = img.getpixel((x, y))
                r = toBinary(r)[:-1] + password_bin[password_bin_index]
                g = toBinary(g)[:-1] + (password_bin[password_bin_index + 1] if password_bin_index + 1 < password_bin_length else '0')
                b = toBinary(b)[:-1] + (password_bin[password_bin_index + 2] if password_bin_index + 2 < password_bin_length else '0')

                img.putpixel((x, y), (int(r, 2), int(g, 2), int(b, 2)))
                password_bin_index += 3

        return img
    except IOError:
        messagebox.showerror("Error", "Unable to open image file.")

def decode_image(image_path, aes_cipher):
    try:
        img = Image.open(image_path)
        width, height = img.size
        binary_data = ""
        total_pixels = width * height
        pixels_checked = 0

        # Extract binary data from the image pixels
        for x in range(width):
            for y in range(height):
                r, g, b = img.getpixel((x, y))
                binary_data += toBinary(r)[-1]
                binary_data += toBinary(g)[-1]
                binary_data += toBinary(b)[-1]
                
                pixels_checked += 1

                # Optional: Display progress or stop if too much data is extracted
                if pixels_checked % 1000 == 0:
                    print(f"Processed {pixels_checked}/{total_pixels} pixels...")

                # Stop if we have enough data (early exit for optimization)
                if len(binary_data) > 100000:  # Arbitrary limit; adjust as needed
                    break

        # Convert binary data to string
        byte_data = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
        decoded_data = "".join([chr(int(byte, 2)) for byte in byte_data])

        # Look for the end marker ($$$) and return the decrypted password
        end_marker = decoded_data.find("$$$")
        if end_marker != -1:
            decrypted_password = aes_cipher.decrypt(decoded_data[:end_marker])
            return decrypted_password

    except IOError:
        print("Error: Unable to open image file.")
    except Exception as e:
        print(f"An error occurred during decoding: {e}")
        
    return ""


class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Image Steganography")

        # Key input field
        self.key_label = tk.Label(root, text="Enter Key:")
        self.key_label.grid(row=0, column=0, padx=5, pady=5)
        self.key_entry = tk.Entry(root, width=40, show="*")
        self.key_entry.grid(row=0, column=1, padx=5, pady=5)

        # Select image for encoding
        self.image_path = ""
        self.select_image_button = tk.Button(root, text="Select Image", command=self.select_image)
        self.select_image_button.grid(row=1, column=0, padx=5, pady=5)

        # Password entry
        self.password_label = tk.Label(root, text="Enter Password:")
        self.password_label.grid(row=2, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(root, width=40, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        # Encode/Decode Buttons
        self.encode_button = tk.Button(root, text="Encode", command=self.encode)
        self.encode_button.grid(row=3, column=0, padx=5, pady=5)
        self.decode_button = tk.Button(root, text="Decode", command=self.decode)
        self.decode_button.grid(row=3, column=1, padx=5, pady=5)

        # Status label
        self.status_label = tk.Label(root, text="")
        self.status_label.grid(row=4, columnspan=2, pady=10)

    def select_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if self.image_path:
            self.status_label.config(text=f"Selected Image: {self.image_path.split('/')[-1]}")

    def encode(self):
        key = self.key_entry.get()
        password = self.password_entry.get()
        if not self.image_path or not key or not password:
            messagebox.showerror("Input Error", "Please fill in all fields and select an image.")
            return

        aes_cipher = AESCipher(key)
        img = encode_image(self.image_path, password, aes_cipher)
        if img:
            save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
            if save_path:
                img.save(save_path)
                self.status_label.config(text="Image encoded and saved successfully.")
            else:
                self.status_label.config(text="Save operation cancelled.")

    def decode(self):
        key = self.key_entry.get()
        if not self.image_path or not key:
            messagebox.showerror("Input Error", "Please enter the key and select an image to decode.")
            return

        aes_cipher = AESCipher(key)
        decrypted_message = decode_image(self.image_path, aes_cipher)
        if decrypted_message:
            self.status_label.config(text=f"Decoded Message: {decrypted_message}")

# Run the application
root = tk.Tk()
app = SteganographyApp(root)
root.mainloop()
