
# Image Steganography with AES Encryption

This project provides a GUI-based application for hiding and retrieving text (passwords or secret messages) within images using steganography and AES encryption. The program uses `tkinter` for the GUI interface, allowing users to easily encrypt, encode, decode, and decrypt messages in images without using the command line.

## Features

- **AES Encryption**: Encrypts text messages using AES-256 encryption before encoding them in images.
- **Steganography**: Hides encrypted messages within image pixels.
- **GUI Interface**: User-friendly interface for encoding and decoding messages, implemented with `tkinter`.
- **Secure Data**: Protects hidden messages with user-defined keys.

## Requirements

- Python 3.x
- Required Python libraries (install using `pip`):
 - `Pillow`: For image processing.
 - `pycryptodome`: For AES encryption.
 - `tkinter`: For the GUI (included with most Python installations).

```bash
pip install pillow pycryptodome
```
## Usage

1.  **Run the Program**: Start the application by running the main script:
    
    bash
    
    Copy code
    
    `python your_script_name.py` 
    
2.  **Encoding (Hiding a Message)**:
    
    -   **Step 1**: Enter an encryption key in the "Enter Key" field.
    -   **Step 2**: Click on  **Select Image to Encode**  and choose an image file.
    -   **Step 3**: Enter the secret message in the "Enter Password" field.
    -   **Step 4**: Click  **Encode & Save**, and select a location to save the new image with the hidden message.
3.  **Decoding (Retrieving a Message)**:
    
    -   **Step 1**: Enter the encryption key used for encoding in the "Enter Key" field.
    -   **Step 2**: Click on  **Select Image to Decode**  and choose the image file with the hidden message.
    -   **Step 3**: The decoded message will appear in the "Decoded Password" field if the key is correct.

## Project Structure

-   **`AESCipher`  Class**: Handles AES encryption and decryption.
-   **GUI Components**: Using  `tkinter`  to handle file selection, encoding, and decoding processes.
-   **Main Application**: Manages encoding the message into the image and decoding it back using steganography and AES.

## Code Overview

The application uses:

-   **AES Encryption**  to secure the message before hiding it within the image.
-   **Steganography**  to embed the encrypted message in the least significant bits of image pixels.
-   **Tkinter GUI**  for a user-friendly interface to facilitate encoding and decoding.

## Important Notes

-   **Image Format**: The program supports  `PNG`  files, as they are lossless and do not compress or alter the data, preserving the hidden message.
-   **Encryption Key**: Ensure that the encryption key used to encode the message is the same as the key used to decode it. Otherwise, the message will not be retrievable.
-   **Image Size**: The message size should be relatively small, as the entire message must fit within the image pixels without significantly altering the image quality.

## Example

### Encoding

1.  Open the application, enter a key (e.g.,  `mysecretkey`), select an image, enter a password or secret message, and save the new image with the hidden message.

### Decoding

1.  Reopen the application, enter the same key (`mysecretkey`), select the image with the hidden message, and retrieve the decoded message.

## License

This project is licensed under the MIT License.

## Acknowledgments

-   **Python Cryptography Toolkit**  - For encryption and decryption operations.
-   **Pillow Library**  - For image processing.
-   **Tkinter**  - For building the GUI interface.

## Contact

