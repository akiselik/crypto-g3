'''
This is the file that will hold the hmac which will be appended to each message
sent between the client and server.

The implementation is based off of: https://en.wikipedia.org/wiki/HMAC

This file is written for the final project of Team 3 of Cryptography & Network Security I taught by
Professor Yener in the Fall '18 semester.
'''

import numpy as np
import sys
import binascii
from sha1_hex import sha1

# converting from input to binary
# credits to stack overflow
def text_to_bits(cti):
    return ''.join('{:08b}'.format(ord(c)) for c in cti)

def text_from_bits(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))

def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

def hmac(key, message, block_size=512, output_size=320):
	'''
	This is the main hmac func.

	Inputs: key - key is expected as a str, using bits and whatnot
	message - the message to be hashed, to be turned to...bits or something idk
	block_size - given in bits in accordance to what our sha1 outputs in terms of length, but says its supposed to be .
	output_size - given in bits in accordance to what our sha1 outputs, but according to wikipedia, it's suppoed to be 20 bytes...
	'''
	# sign = ""
	# key_plus = ""
	# # make the key a string if it ain't, which it won't be
	# if type(key) == str:
	# 	key_plus = "{:0160b}".format(int(key, 10)) # now should be 0 or 1 * 160 or something

	# if len(key_plus) > block_size:
	# 	key_plus = sha1(key_plus)

	# if len(key_plus) < block_size:
	# 	key_plus = "{:0160b}".format(key_plus)

	sign = None

	# I'm just going to deal with bits because that's what I'm familiar with
	if type(key) == str:
		key_bits = "{:b}".format(int(key))
	elif type(key) == int:
		key_bits = "{:b}".format(key)
	else:
		print("Have the key be of type str or type int, please! Returning None...")
		return None

	# Since we decided on keys with a length of <redacted>, shouldn't ever hit this block...or will it?
	if len(key_bits) > block_size:
		new_key = sha1(str(key_bits, 2))
		key_bits = "{:b}".format(key)

	# might hit here all the time
	if len(key_bits) < block_size:
		to_pad_by = block_size - len(key_bits)
		# construct someting to pad to the right
		pad_arr = [b for b in key_bits]
		for i in range(to_pad_by):
			pad_arr.insert(0, '0')
		key_bits = ''.join(pad_arr)

	# key should now be what we want, in bits anyway

	# now for o_pad, i_pad, in bits because I like bits
	o_pad = int(key_bits, 2) ^ int((0x5c * (512/8))) # divided by 8 because original has in bytes
	i_pad = int(key_bits, 2) ^ int((0x36 * (512/8)))

	o_pad_bits = "{:b}".format(o_pad)
	i_pad_bits = "{:b}".format(i_pad)

	# now to construct the things to hash...
	first_to_hash = sha1((str(o_pad) + message))
	sign = sha1(str(o_pad) + first_to_hash)

	return sign

if __name__ == '__main__':
	print("This is (maybe) what an HMAC does.")
	user_input = input("Enter a message you would like to have signed: ")
	print("For this proof of concept, a key is selected for you (19).")
	print("The HMAC to be appended to the end of the encrypted message is:", hmac(19, user_input))
