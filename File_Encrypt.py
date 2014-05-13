#File_Encrypt.py
import os, random, struct, sys, hashlib, click
from Crypto.Cipher import AES
from PIL import Image
from Crypto.Cipher import DES
from Crypto import Random

def decryptPixelComponent(component, key):
    decryptor = AES.new(key, AES.MODE_ECB)
    component_hash = hashlib.sha256(str(component)).digest()
    component = decryptor.decrypt(component_hash).encode('hex')
    #print int(component, 16)
    return int(component, 16)

def decryptPixel(pixel, key):
    (red, green, blue) = pixel
    return (decryptPixelComponent(red, key),
            decryptPixelComponent(green, key),
            decryptPixelComponent(blue, key))

def encryptPixelComponent(component, key):
    encryptor = AES.new(key, AES.MODE_ECB)
    component_hash = hashlib.sha256(str(component)).digest()
    component = encryptor.encrypt(component_hash).encode('hex')
    return int(component, 16) % 256

def encryptPixel(pixel, key):
    (red, green, blue) = pixel
    return (encryptPixelComponent(red, key),
            encryptPixelComponent(green, key),
            encryptPixelComponent(blue, key))

def AES_CBC_Component(component, key):
    iv = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    component_hash = hashlib.sha256(str(component)).digest()
    component = encryptor.encrypt(component_hash).encode('hex')
    return int(component, 16) % 256

def AES_CBC_Pixel(pixel, key):
    (red, green, blue) = pixel
    return (AES_CBC_Component(red, key),
            AES_CBC_Component(green, key),
            AES_CBC_Component(blue, key))

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

@click.group()
def init():
    pass

@click.command()
@click.argument('input_filename')
@click.argument('password')
@click.option('-o', default="file_encrypt.out", help='Output filename')
@click.option('--cipher', default="AES_ECB", help='The encryption to be used on the file')
def encrypt(input_filename, password, o, cipher):
    ciphers = ['AES_ECB', 'AES_CBC', 'DES']

    key = generate_key(password)
    #Loading Pixel Data
    im = Image.open(input_filename)
    pix = im.load()
    size = im.size
    print "Filesize: " + str(size)
    for x in range(size[0]):
        for y in range (size[1]):
            pixel = pix[x,y]
            #print (x,y) #DEBUG
            if cipher == ciphers[0]:
                pix[x,y] = encryptPixel(pixel, key)
            if cipher == ciphers[1]:
                pix[x,y] = AES_CBC_Pixel(pixel, key)
    im.save(o)

init.add_command(encrypt)

@click.command()
@click.argument('input_filename')
@click.argument('password')
@click.option('-o', default="file_decrypt.out", help='Output filename')
@click.option('--cipher', default="AES_ECB", help='The encryption to be used for decryption')
def decrypt(input_filename, output_filename, password, cipher):
    pass

init.add_command(decrypt)

if __name__ == '__main__':
    init()
