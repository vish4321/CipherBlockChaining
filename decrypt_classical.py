#!/usr/bin/env python

import sys
from BitVector import *                                                       #(A)

if len(sys.argv) != 3:
    sys.exit('''Needs two command-line arguments, one for '''
             '''the message file and the other for the '''
             '''encrypted output file''')

PassPhrase = "Cryptography is the art of  secret writing"

BLOCKSIZE = 64
numbytes = BLOCKSIZE // 8

bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
for i in range(0,len(PassPhrase) // numbytes):
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
    bv_iv ^= BitVector( textstring = textstr )

key = None
if sys.version_info[0] == 3:
    key = input("\nEnter key: ")
else:                                                                         
    key = raw_input("\nEnter key: ")
key = key.strip()

key_bv = BitVector(bitlist = [0]*BLOCKSIZE)
for i in range(0,len(key) // numbytes):
    keyblock = key[i*numbytes:(i+1)*numbytes]
    key_bv ^= BitVector( textstring = keyblock )

msg_encrypted_bv = BitVector( size = 0 )

previous_block = bv_iv
bv = BitVector( filename = sys.argv[1] )
while (bv.more_to_read):
    bv_read1 = bv.read_bits_from_file(2*BLOCKSIZE)
    bv_read = BitVector(hexstring = bv_read1.get_bitvector_in_ascii())
    bv_read_temp = bv_read.deep_copy()
    bv_read ^= key_bv
    bv_read ^= previous_block
    previous_block = bv_read_temp
    msg_encrypted_bv += bv_read

outputhex = msg_encrypted_bv.get_bitvector_in_ascii()
FILEOUT = open(sys.argv[2], 'w', encoding='utf-8')
FILEOUT.write(outputhex)
FILEOUT.close()