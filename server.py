import socket
from Cryptodome.Cipher import AES
#from Crypto.Cipher import AES
from Cryptodome.Random import get_random_bytes
#from cryptography.hazmat.primitives.asymmetric import rsa
import rsa

#Generating public and private keys
(pub_key, priv_key) = rsa.newkeys(1024)
a = pub_key.save_pkcs1(format='DER')

def server_program():
    # establish connection
    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection request from: " + str(address))
    print("Performing Handshake")

    #send public key to the client
    conn.send(a)
    #receive 
    mess=conn.recv(2048)
    messi=rsa.decrypt(mess, priv_key).decode()
    if(messi!="clientpass"):
        conn.close()
        return 0
    aeskey = get_random_bytes(16)
    #aeskey = AES.new(key)
    #print(aeskey)
    signa=rsa.sign(aeskey, priv_key,'MD5')
    
    conn.send(aeskey)
    conn.send(signa)

    ciphertext=conn.recv(16)
    print("Ciphertext1:",ciphertext)
    nonce=conn.recv(16)
    print("noncee1:",nonce)
    tag=conn.recv(16)
    print("Tag1:",tag)
    #noncee=conn.recv(2048)
    #print("noncee1:",noncee)
    print("aeskey:",aeskey)
    #file_in = open("encryptedfile.bin", "rb")
    #nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    #print("Ciphertext2:",ciphertext)
    #print("Tag2:",tag)
    #print("noncee2:",nonce)
    ciphery = AES.new(aeskey, AES.MODE_EAX,nonce)
    plaintext = ciphery.decrypt(ciphertext)
    final=plaintext.decode('UTF-8')
    print(final) 
    #print(plaintext)
    if(final=="hello"):
        cipher = AES.new(aeskey, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(b"hello to you too")
        conn.send(ciphertext)
        conn.send(cipher.nonce)
        conn.send(tag)
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024).decode()
        if not data:
            # if data is not received break
            break
        print("from connected user: " + str(data))
        data = input(' -> ')
        conn.send(data.encode())  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()