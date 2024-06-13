# Install pycryptodome
import sys
from Cryptodome.Cipher import AES
from Crypto.Hash import SHA256

def decrypt_config_f(encrypted_config_filename, decrypted_destination_filename, password):
    h = SHA256.new()
    h.update(password.encode())
    key =  h.digest()
    with open(encrypted_config_filename, "rb") as fin:
        fin.read(26)
        iv = fin.read(12)
        tag = fin.read(16)
        try:
            cipher = AES.new(key, nonce=iv, mode=AES.MODE_GCM)
            pt = cipher.decrypt_and_verify(fin.read(), tag)
        except Exception as e:
            print("Decryption Error: %s - wrong password?" % str(e))
            sys.exit(1)
    with open(decrypted_destination_filename + ".gz", 'wb') as f_out:
        f_out.write(pt)


if __name__ == "__main__":
    decrypt_config_f(sys.argv[1], sys.argv[2], sys.argv[3])