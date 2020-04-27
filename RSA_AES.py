from Crypto.PublicKey import RSA
import random
from Crypto.Random import get_random_bytes
import cryptography
from Crypto.Cipher import AES, PKCS1_OAEP


def RSAdec(numbits,filename,keyname):
    #input_file = open(filename + '.bin', 'rb')
    temp=filename[:len(filename)-10]  
    output_file = open(temp , 'wb')

      
    code = 'nooneknows'

    with open(filename, 'rb') as fobj:
        private_key = RSA.import_key(open(keyname).read(),passphrase=code)
        enc_session_key, nonce, tag, ciphertext = [ fobj.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    output_file.write(data)
    print("Decryption completed")

def RSAenc(filename,numbits,nameoffile2):

    f=open(filename,'rb')
    data=f.read()

    encfilename=filename+".encrypted"

    with open(encfilename, 'wb') as out_file:
        recipient_key = RSA.import_key(open(nameoffile2).read())
        session_key = get_random_bytes(16)
    
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        out_file.write(cipher_rsa.encrypt(session_key))
    
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        #data = b'blah blah blah Python blah blah'
    
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        
        out_file.write(cipher_aes.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)
    print("Encryption completed")

def createRSAKeyFiles(numbits):

    nameoffile1="privateKeyRSA"+str(numbits)
    nameoffile1=nameoffile1+".pem"

    nameoffile2="publicKeyRSA"+str(numbits)
    nameoffile2=nameoffile2+".pem"
    
    code = 'nooneknows'
    key = RSA.generate(numbits)
    encrypted_key = key.exportKey(passphrase=code, pkcs=8, protection="scryptAndAES128-CBC")
    with open(nameoffile1, 'wb') as f:
        f.write(encrypted_key)
    
    with open(nameoffile2, 'wb') as f:
        f.write(key.publickey().exportKey())
    
    print("Public Key named "+nameoffile2+" has been created" )
    print("Use this file name while encryption")

def createAESKeyFiles(numbits):
    key = get_random_bytes(numbits) 
    
    #keyfilename="KeyforAES.txt"
    keyfilename="KeyAES"+str(numbits*8)
    keyfilename=keyfilename+".txt"
    key_file=open(keyfilename,"wb")
    key_file.write(key)

    print("Key named "+keyfilename+" has been created" )
    print("Use this file name while encryption")

def AESenc(numbits,filename1,filename2):
    buffer_size = 65536 # 64kb

    f=open(filename2,"rb")
    key=f.read()

    input_file = open(filename1, 'rb')
    #olmazsa .encrypted olarak değiştir
    output_file = open(filename1 + '.bin', 'wb')
    cipher_encrypt = AES.new(key, AES.MODE_CFB)
    output_file.write(cipher_encrypt.iv)
    buffer = input_file.read(buffer_size)

    while len(buffer) > 0:
        ciphered_bytes = cipher_encrypt.encrypt(buffer)
        output_file.write(ciphered_bytes)
        buffer = input_file.read(buffer_size)

    # Close the input and output files
    input_file.close()
    output_file.close()
    print("Encryption completed")

def AESdec(numbits,filename,keyname):
    buffer_size = 65536 # 64kb
    keyfilename=keyname
    
    f=open(keyfilename,"rb")
    key=f.read()

    input_file = open(filename , 'rb')
    file1=filename[:len(filename)-4]
    output_file = open(file1 , 'wb')

    # Read in the iv
    iv = input_file.read(16)

    # Create the cipher object and encrypt the data
    cipher_encrypt = AES.new(key, AES.MODE_CFB, iv=iv)

    # Keep reading the file into the buffer, decrypting then writing to the new file
    buffer = input_file.read(buffer_size)
    while len(buffer) > 0:
        decrypted_bytes = cipher_encrypt.decrypt(buffer)
        output_file.write(decrypted_bytes)
        buffer = input_file.read(buffer_size)

    # Close the input and output files
    input_file.close()
    output_file.close()
    print("Decryption completed")

while True:
    print("Main Menu")
    print("*******************************")

    #encryption or decryption
    print("Please select one of the options below")
    print("1.Encryption")
    print("2.Decryption")
    EncOrDec=input("Your choice is ")

    print("*******************************")
    print("Please choose crypography algorithm and length of the key")
    print("1. AES with 128 bits")
    print("2. AES with 192 bits")
    print("3. AES with 256 bit")
    print("4. RSA with 1024 bits")
    print("5. RSA with 2048 bits")
    user_choice=input("Your choice is ")
   
   #Enc
    if EncOrDec=="1" and user_choice=="1":
        filename=input("Please enter a file name ")
        createAESKeyFiles(16)
        keyfilename=input("Please enter the file name for Key ")
        if keyfilename== "KeyAES128.txt":
            AESenc(16,filename,keyfilename)
        else:
            print("You entered a wrong filename for key")
        break


    elif EncOrDec=="1" and user_choice=="2":
        filename=input("Please enter a file name ")
        createAESKeyFiles(24)
        keyfilename=input("Please enter the file name for Key ")
        if keyfilename== "KeyAES192.txt":
            AESenc(24,filename,keyfilename)
        else:
            print("You entered a wrong filename for key")
        break


    elif EncOrDec=="1" and user_choice=="3":
        filename=input("Please enter a file name ")
        createAESKeyFiles(32)
        keyfilename=input("Please enter the file name for Key ")
        if keyfilename== "KeyAES256.txt":
            AESenc(32,filename,keyfilename)
        else:
            print("You entered a wrong filename for key")
        break


    elif EncOrDec=="1" and user_choice=="4":
        filename=input("Please enter a file name ")
        createRSAKeyFiles(1024)
        keyfilename=input("Please enter the file name for Public Key ")
        if keyfilename== "publicKeyRSA1024.pem":
            RSAenc(filename,1024,keyfilename)
        else:
            print("You entered a wrong filename for key")
        break


    elif EncOrDec=="1" and user_choice=="5":
        filename=input("Please enter a file name ")
        createRSAKeyFiles(2048)
        keyfilename=input("Please enter the file name for Public Key ")
        if keyfilename== "publicKeyRSA2048.pem":
            RSAenc(filename,2048,keyfilename)
        else:
            print("You entered a wrong filename for key")
        break

    #Dec
    elif EncOrDec=="2" and user_choice=="1":
        filename=input("Please enter a file name ")
        keyname=input("Please enter a file name for key ")
        if keyname== "KeyAES128.txt":
            AESdec(16,filename,keyname)
        else:
            print("You entered a wrong filename for key")
        break


    elif EncOrDec=="2" and user_choice=="2":
        filename=input("Please enter a file name ")
        keyname=input("Please enter a file name for key ")
        if keyname== "KeyAES192.txt":
            AESdec(24,filename,keyname)
        else:
            print("You entered a wrong filename for key")
        
        break


    elif EncOrDec=="2" and user_choice=="3":
        filename=input("Please enter a file name ")
        keyname=input("Please enter a file name for key ")
        if keyname== "KeyAES256.txt":
            AESdec(32,filename,keyname)
        else:
            print("You entered a wrong filename for key")
        break


    elif EncOrDec=="2" and user_choice=="4":
        filename=input("Please enter a file name ")
        keyname=input("Please enter the file name for Private Key ")
        if keyname== "privateKeyRSA1024.pem":
            RSAdec(1024,filename,keyname)
        else:
            print("You entered a wrong filename for key")
        
        break


    elif EncOrDec=="2" and user_choice=="5":
        filename=input("Please enter a file name ")
        keyname=input("Please enter a file name for Private Key ")
        if keyname== "privateKeyRSA2048.pem":
            RSAdec(2048,filename,keyname)
        else:
            print("You entered a wrong filename for key")
        break


    else:
        print("Invalid input, Please try again !")
        print("")