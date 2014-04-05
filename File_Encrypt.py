#File_Encrypt.py
import os, random, struct
from Crypto.Cipher import AES
import hashlib
import sys
from PIL import Image
from Crypto.Cipher import DES

def encryptPixelComponent(component, key):
    #encryptor = AES.new(key, AES.MODE_ECB)
    encryptor = DES.new("testtest", DES.MODE_ECB)
    component_hash = hashlib.sha256(str(component)).digest()
    component = encryptor.encrypt(component_hash).encode('hex')
    #print int(component, 16)
    return int(component, 16) % 256;

def encryptPixel(pixel, key):
    (red, green, blue) = pixel
    return (encryptPixelComponent(red, key),
            encryptPixelComponent(green, key),
            encryptPixelComponent(blue, key))

def generate_key(password):
    key = hashlib.sha256(str(password)).digest()
    return key

#http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))

#http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)

def main():
    # Input checking
    if (len(sys.argv) != 2):
        print "Usage: File_encypt.py [encrypt]/[decrypt]"
        sys.exit()

    # Encryption
    elif (sys.argv[1] == "encrypt"):
        print "Enter input filename:"
        input_filename = raw_input()
        print "Enter output filename:"
        output_filename = raw_input()
        print "Enter password to encrypt with:"
        password = raw_input()
        key = generate_key(password)
        #Loading Pixel Data
        im = Image.open(input_filename)
        pix = im.load()
        size = im.size
        print size
        for x in range(size[0]):
            for y in range (size[1]):
                pixel = pix[x,y]
                #print pixel
                print (x,y)
                pix[x,y] = encryptPixel(pixel, key)
        im.save(output_filename)
        sys.exit()
        #encrypt_file(key, input_filename, output_filename)

    # Decryption
    elif (sys.argv[1] == "decrypt"):
        print "Enter input filename:"
        input_filename = raw_input()
        print "Enter output filename:"
        output_filename = raw_input()
        print "Enter password to encrypt with:"
        password = raw_input()
        key = generate_key(password)
        decrypt_file(key, input_filename, output_filename)

    else:
        print "Usage: File_encypt.py [encrypt]/[decrypt]"
        sys.exit()


main()

import Image
import sys
from Crypto.Cipher import DES



def main():
    imageName = sys.argv[1]
    im = Image.open(imageName)
    pix = im.load()
    size = im.size
    for x in range(size[0]):
        for y in range (size[1]):
            pixel = pix[x,y]
            #print pixel
            pix[x,y] = encryptPixel(pixel, key)
                        
    enc = im
    enc.save(imageName + ".enc.jpg")
    
main()
