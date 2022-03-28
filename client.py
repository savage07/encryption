import socket
#import cryptography
import rsa
from Cryptodome.Cipher import AES
#from Crypto.Cipher import AES
from Cryptodome.Random import get_random_bytes

def client_program():
    ##Establishing web-socket connection
    host = socket.gethostname()  
    port = 5000  
    client_socket = socket.socket()
    client_socket.connect((host, port)) 
    #receive public key from server
    key=client_socket.recv(1024)
    #print(key)
    pkey = rsa.key.PublicKey.load_pkcs1(key, format='DER')
    message = 'clientpass'#acts as the password P0
    crypto = rsa.encrypt(message.encode(), pkey)#encrypt using public key
    client_socket.send(crypto)#

    aeskey=client_socket.recv(2048)
    signa=client_socket.recv(2048)
    #print(aeskey)
    try:
        rsa.verify(aeskey, signa, pkey)
        print("AES key verified")
    except:
        print("AES key not verified")
        return 0
    
    cipher = AES.new(aeskey, AES.MODE_EAX)
    messagee=b"hello"
    ciphertext, tag = cipher.encrypt_and_digest(messagee)
    #tosend=(ciphertext,tag)
    print(ciphertext)
    print(tag)
    print(aeskey)


    #cipher = AES.new(aeskey, AES.MODE_EAX,cipher.nonce)
    #plaintext = cipher.decrypt_and_verify(ciphertext,tag)
    #print(plaintext)
    client_socket.send(ciphertext)
    client_socket.send(cipher.nonce)
    #client_socket.send(cipher.nonce)
    print(cipher.nonce)
    client_socket.send(tag)

    ciphertext=client_socket.recv(16)
    nonce=client_socket.recv(16)
    tag=client_socket.recv(16)
    ciphery = AES.new(aeskey, AES.MODE_EAX,nonce)
    plaintext = ciphery.decrypt(ciphertext)
    print(plaintext.decode())
    message = input(" -> ")  # take input
    while message.lower().strip() != 'bye':
        client_socket.send(message.encode())  # send message
        data = client_socket.recv(1024).decode()  # receive response

        print('Received from server: ' + data)  # show in terminal

        message = input(" -> ")  # again take input

    client_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()