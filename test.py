from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

#define our data
data=b"SECRETDATA"

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)
print(ciphertext)

file_out = open("encryptedfile.bin", "wb")
[ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
file_out.close()

#################################################################

file_in = open("encryptedfile.bin", "rb")
nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

#the person decrypting the message will need access to the key
cipher = AES.new(key, AES.MODE_EAX, nonce)
print(key)
data = cipher.decrypt_and_verify(ciphertext, tag)
print(data)
print(data.decode('UTF-8')) 