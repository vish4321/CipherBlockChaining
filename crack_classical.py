import sys
from BitVector import *
import random
import string
import collections
import binascii
import math

#IMPORTANT: Code will only work for python3 

# XORs two bitvectors
def bvxor(a, b):
    c_bv = a ^ b
    return c_bv.get_bitvector_in_ascii()

if len(sys.argv) != 3:
    sys.exit('''Needs two command-line arguments, one for '''
             '''the input ciphertext file and the other for the '''
              '''decrypted output file''')

PassPhrase = "Cryptography is the art of  secret writing"

BLOCKSIZE = 64
numbytes = BLOCKSIZE // 8

bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
for i in range(0,len(PassPhrase) // numbytes):
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
    bv_iv ^= BitVector( textstring = textstr )

ciphers = []
final_key = [None]*8
known_key_positions = set()
msg_encrypted_bv = BitVector(size = 0)
target_cipher = ''
bv = BitVector( filename = sys.argv[1] )
previous_block = BitVector(size=BLOCKSIZE)
blockCounter = 1
while (bv.more_to_read):
    bv_read1 = bv.read_bits_from_file(2*BLOCKSIZE)
    bv_read = BitVector(hexstring = bv_read1.get_bitvector_in_ascii())
    msg_encrypted_bv = bv_read ^ previous_block
    previous_block = bv_read.deep_copy()
    ciphers.append(msg_encrypted_bv)
    blockCounter += 1

#END OF FIRST PART
#SECOND PART STARTS HERE
    
THRESHOLD = 0.7

ciphers.pop(0)
space_bv = BitVector(textstring = ' '*8)

for current_index, ciphertext in enumerate(ciphers):
    
	counter = collections.Counter()
	for index, ciphertext2 in enumerate(ciphers):
		if current_index != index:
			for indexOfChar, char in enumerate(bvxor(ciphertext, ciphertext2)):
				if char in string.printable and char.isalpha(): counter[indexOfChar] += 1
	knownSpaceIndexes = []

	for ind, val in counter.items():
		if val >= math.floor(THRESHOLD*blockCounter): knownSpaceIndexes.append(ind)
	xor_with_spaces = bvxor(ciphertext, space_bv)
	for index in knownSpaceIndexes:
		final_key[index] = binascii.hexlify(bytes(xor_with_spaces[index].encode(encoding='ascii'))).decode('ascii')
		known_key_positions.add(index)

final_key_hex = ''.join([val if val is not None else '00' for val in final_key])
print('Guessed key: ' + final_key_hex)

key_bv = BitVector(hexstring = final_key_hex)
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