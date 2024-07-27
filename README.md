# PDF-Encryption Python 3.11
Simple Tools to encrypt and decrypt PDF Files using AES Encryption in CBC (Cipher Block Chaining) mode


# How To Use 
1. First install pip cryptography and tkinkter
   ```json
   pip install cryptography
   pip install tkinter
   ```
2. Run ```python Encryption.py``` Or ```python decrypt_tools.py```
3. If there is a Manual Input option in the Encryption tools, then you must input Manually with a length of 32 bytes and if you do not select the manual input option, it will automatically create a random key for you and it will be automatically saved in key.json.
4. If you have encrypted your PDF, you must see key.json if you want to decrypt the encrypted PDF.
5. If the Decrypt tool displays a manual key input, you must input the key manually by taking the key = xxxx in the key.json file or you load the key.json file by clicking no in the option selection.

# TO DO 
I want to create an application to read encrypted files from this tool in the future.
