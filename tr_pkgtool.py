import zlib
import os
from Crypto.Cipher import AES
from argparse import ArgumentParser

def build_parser():
    parser = ArgumentParser()
    parser.add_argument('pkg_path')
    return parser

def decrypt(data):
    decrypt_data=list(data)
    aes_key=[0x0D,0x68,0x07,0x6F,0x0A,0x09,0x07,0x6C,0x65,0x73,
    0x0D,0x75,0x6E,0x0A,0x65,0x0D]
    xor_key=[0x05, 0x5B, 0xCB, 0x64, 0xFB, 0xC2, 0xCE, 0xB4, 0x77, 0x8B, 
    0x1B, 0xB8, 0xE9, 0xB5, 0x9C, 0xC6]
    length=len(data)
    i=0
    if length>=16:
        group_num=length//16
        aes=AES.new(bytes(aes_key),AES.MODE_ECB)
        decrypt_data[0:group_num*16]=aes.decrypt(bytes(data[0:group_num*16]))
        i=group_num*16
    while i<length:
        decrypt_data[i]=data[i]^xor_key[i%16]
        i=i+1
    return bytes(decrypt_data)

def decrypt2(data):
    decrypt_data=list(data)
    aes_key=[0xFD,0xD7,0x15,0xCB,0xBE,0xBF,0xA5,0xFF,0xEF,0x9E,
    0xED,0x97,0xCE,0x96,0xD3,0x0F,0x4C,0xDC,0xA0,0x1D,
    0xAF,0x5F,0xCF,0xA2,0xD8,0xB1,0x58,0x08,0xB9,0xB6,
    0xC1,0x0A]
    xor_key=[0x20, 0x44, 0xB2, 0xA3, 0x63, 0xC7, 0x47, 0x88, 0x4D, 0x1E, 
    0x2F, 0x12, 0x90, 0x39, 0x3C, 0x8E]
    length=len(data)
    i=0
    if length>=16:
        group_num=length//16
        aes=AES.new(bytes(aes_key),AES.MODE_ECB)
        decrypt_data[0:group_num*16]=aes.decrypt(bytes(data[0:group_num*16]))
        i=group_num*16
    while i<length:
        decrypt_data[i]=data[i]^xor_key[i%16]
        i=i+1
    return bytes(decrypt_data)

def read_str(bt):
    i=0
    s=''
    while bt[i]!=0:
        s+=chr(bt[i])
        i=i+1
    return s

def main():
    parser=build_parser()
    options=parser.parse_args()
    pkg_path=options.pkg_path
    pkg_name=os.path.basename(pkg_path)
    pkg_name=os.path.splitext(pkg_name)[0]
    pkg=open(pkg_path,'rb')
    file_header=pkg.read(12)
    file_header=decrypt(file_header).decode()
    if file_header!='ACAC35E5-4B7':
        print('Not a valid .pkg file or decryption key has changed')
        return
    pkg.seek(0x14,0)
    offset=int.from_bytes(pkg.read(4),byteorder='little') #compressed file entry info offset
    pkg.seek(offset,0)
    pkg.seek(0x4,1)
    file_num=int.from_bytes(pkg.read(4),byteorder='little') #file number
    pkg.seek(0x4,1)
    num=0
    #unpack pkg
    while(num<file_num):
        entry_size=int.from_bytes(pkg.read(4),byteorder='little') #compressed file entry data size
        entry_data=pkg.read(entry_size) #compressed file entry data
        next_entry=pkg.tell()
        decompressed_entry_data=zlib.decompress(entry_data)
        file_path=os.path.join(pkg_name,read_str(decompressed_entry_data))
        file_dir=os.path.dirname(file_path)
        part_num=int.from_bytes(decompressed_entry_data[0x410:0x414],byteorder='little') #compressed file data part total number
        offset=int.from_bytes(decompressed_entry_data[0x414:0x418],byteorder='little') #file body offset
        pkg.seek(offset,0)
        decrypted_file_data=bytes()
        for i in range(part_num):
            pkg.seek(0x8,1)
            file_size=int.from_bytes(pkg.read(4),byteorder='little') #encrypted file data size
            pkg.seek(0x4,1)
            encrypt_type=int.from_bytes(pkg.read(4),byteorder='little')
            file_data=pkg.read(file_size) #encrypted file data
            if encrypt_type&1:
                file_data=zlib.decompress(file_data)
            if encrypt_type&2:
                file_data=decrypt2(file_data)
            decrypted_file_data+=file_data
        if not os.path.exists(file_dir):
            os.makedirs(file_dir)
        export_file=open(file_path,'wb')
        export_file.write(decrypted_file_data)
        export_file.close()
        pkg.seek(next_entry,0)
        num=num+1
    pkg.close()
    print('Unpack done')

if __name__=='__main__':
    main()

