'''
This is the TOY-DES implementation for Crypto & Netsec 1 with Prof Bulent Yener
in Fall '18. Hooray.
'''

import numpy as np
import sys
import binascii # library to convert strings to binary
import socket
import random

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

# functions for generating the keys

# how the heck am I going to get the initial key? It's also 10 bits...

def key_IP(key):
	# this applies P10 from the slides
	# 3 5 2 7 4 10 1 9 8 6 index'd by 1
	# remember, I got strings lol

	# so this, again, just means that the first char in our key has to be
	# the 3rd of the input.
	permuted_key = ["0" for i in range(10)]
	# print(permuted_key)
	permuted_key[0] = key[2]
	permuted_key[1] = key[4]
	permuted_key[2] = key[1]
	permuted_key[3] = key[6]
	permuted_key[4] = key[3]
	permuted_key[5] = key[9]
	permuted_key[6] = key[0]
	permuted_key[7] = key[8]
	permuted_key[8] = key[7]
	permuted_key[9] = key[5]
	real_p_key = ""
	for i in range(len(permuted_key)):
		real_p_key += permuted_key[i]
	return "{:010b}".format(int(real_p_key, 2))

def key_splitter(P10_key):
	# this function takes the P10_key from key_IP and splits
	# it up into two 5-bit parts.
	first_5bit = ""
	second_5bit = ""
	for i in range(0,5):
		first_5bit += P10_key[i]
	for i in range(5,10):
		second_5bit += P10_key[i]

	return "{:05b}".format(int(first_5bit,2)), "{:05b}".format(int(second_5bit,2))

def left_shifter(key_5bit):
	# this takes a 5bit key half
	# and left-shifts it
	new_num = int(key_5bit, 2) << 1
	new_num_str = "{:05b}".format(new_num) # need to make sure the return is 5-bit too.
	return new_num_str

def P8_Permuter(half1, half2):
	# this takes the two halves, combines them, and permutes
	# them with P8: 6 3 7 4 8 5 10 9
	to_permute = half1 + half2 # should work as they're both 5-bit strings
	# print(to_permute)
	permuted = ["0" for i in range(8)]
	permuted[0] = to_permute[5]
	permuted[1] = to_permute[2]
	permuted[2] = to_permute[6]
	permuted[3] = to_permute[3]
	permuted[4] = to_permute[7]
	permuted[5] = to_permute[4]
	permuted[6] = to_permute[9]
	permuted[7] = to_permute[8]
	# now to actually make it a usable key
	final_key = ""
	for i in range(len(permuted)):
		final_key += permuted[i]

	return "{:08b}".format(int(final_key, 2)) # remember, this is 8 bits

def key_getter(initial_key):
	# this is the overall function for getting the keys
	IP = key_IP(initial_key)
	half1, half2 = key_splitter(IP)
	ls_half1 = left_shifter(half1)
	ls_half2 = left_shifter(half2)
	K1 = P8_Permuter(ls_half1, ls_half2)
	ls_ls_half1 = left_shifter(ls_half1)
	ls_ls_half2 = left_shifter(ls_half2)
	K2 = P8_Permuter(ls_ls_half1, ls_ls_half2)
	return "{:08b}".format(int(K1, 2)), "{:08b}".format(int(K2, 2))

# functions for generating the cipher

def plain_text_IP(pt):
	# function for IP of 8-bit plaintext. Takes 8 bit block
	# Initial permutation of bit positions is 2 6 3 1 4 8 5 7
	permuted = ["0" for i in range(8)]
	permuted[0] = pt[1]
	permuted[1] = pt[5]
	permuted[2] = pt[2]
	permuted[3] = pt[0]
	permuted[4] = pt[3]
	permuted[5] = pt[7]
	permuted[6] = pt[4]
	permuted[7] = pt[6]
	# now to actually form the thing
	permuted_final = ""
	for i in range(len(permuted)):
		permuted_final += permuted[i]

	return "{:08b}".format(int(permuted_final, 2))

def split_pt(pt):
	# this function takes the pt and splits it up into two 4-bit parts.
	# this is definetly working.
	first_4bit = ""
	second_4bit = ""
	for i in range(0,4):
		first_4bit += pt[i]

	for i in range(4, 8):
		second_4bit += pt[i]

	# print("The results are", first_4bit, "and", second_4bit, "from", pt)
	return "{:04b}".format(int(first_4bit, 2)), "{:04b}".format(int(second_4bit, 2))

def xor_4_bit_strings(pt1, pt2):
	# this function takes the 4-bit strings and xor's them? Recombines them? Think it's xor.
	# it is xor. I can do this by using the carrot ^, int('<insert bit string here', 2)
	# and then getting it in 4bit format is "{:04b}"

	# this definetly works
	int_result = int(pt1, 2) ^ int(pt2, 2)
	result_str = "{:04b}".format(int_result)

	return result_str

def xor_8_bit_strings(pt1, pt2):
	# this function is for xor'ing 8-bit binary strings after
	# I realized I'd need them for the strings
	int_result = int(pt1, 2) ^ int(pt2, 2)
	result_str = "{:08b}".format(int_result)

	return result_str

def sbox0(bits):
	# this function is the sbox0 from slide 73.
	# first, it defines the values of the sbox
	# as a 2D array, then computes the
	# row/column index, finds the
	# value, and returns the 2-bit
	# representation of it.
	box = [[1, 0, 3, 2], \
		  [3, 2, 1, 0], \
		  [0, 2, 1, 3], \
		  [3, 1, 3, 2]]
	row = bits[0] + bits[3] # this is the binary
	# need to have the row be a decimal value
	row_i = int(row, 2)
	# print("The row index is: ", row_i)
	# same thing for the column
	col = bits[1] + bits[2]
	col_i = int(col, 2)
	# print("The column index is: ", col_i)
	val_in_dec = box[row_i][col_i]
	val_in_bin = "{:02b}".format(val_in_dec)
	# print("The value gotten is: ", val_in_dec, "which in binary is: ", val_in_bin)
	return val_in_bin

def sbox1(bits):
	# literally the exact same as sbox0 just different box vals
	box = [[0, 1, 2, 3], \
		  [2, 0, 1, 3], \
		  [3, 0, 1, 0], \
		  [2, 1, 0, 3]]
	row = bits[0] + bits[3] # this is the binary
	# need to have the row be a decimal value
	row_i = int(row, 2)
	# print("The row index is: ", row_i)
	# same thing for the column
	col = bits[1] + bits[2]
	col_i = int(col, 2)
	# print("The column index is: ", col_i)
	val_in_dec = box[row_i][col_i]
	val_in_bin = "{:02b}".format(val_in_dec)
	# print("The value gotten is: ", val_in_dec, "which in binary is: ", val_in_bin)
	return val_in_bin

def F_function(half_pt, key):
	# this function takes a 4-bit part of the pt and
	# a 8-bit key and follows slide 73. First, it Expands and
	# permutes the half_pt, then it XOR's that with the 8bit key,
	# then it splits up into two 4-bit parts, puts those 4-bit parts
	# into the S-Boxes, combines the resulting two 2-bit parts into one
	# 4 bit part, P4 permutation happens, and it returns the 4-bit.
	# this is gonna be a big one.

	# Expansion + Permutation
	permute_list = ["0" for i in range(8)] # list to help w/ the expansion
	permute_list[0] = half_pt[3]
	permute_list[1] = half_pt[0]
	permute_list[2] = half_pt[1]
	permute_list[3] = half_pt[2]
	permute_list[4] = half_pt[1]
	permute_list[5] = half_pt[2]
	permute_list[6] = half_pt[3]
	permute_list[0] = half_pt[0]
	new_8_bit = "" # the new digit
	for i in range(len(permute_list)):
		new_8_bit += permute_list[i]

	# next, the slide calls for the bits to be XOR'd with the key
	# I'm calling it shuffling since XOR will shuffle the bits around
	shuffling = xor_8_bit_strings(new_8_bit, key)

	# the next thing to do is to split up the bits, and even though
	# the function to split stuff was designed for 8-bit plaintext, it works here
	# too. left and right refer to the bits in the branches of the tree on the slide
	left, right = split_pt(shuffling)

	# now the sboxes are used
	left_2_bit = sbox0(left)
	right_2_bit = sbox1(right)

	# left 2bit is 1, 2 and right 2 bit is 3, 4 for the permute
	# now one final Permutation 4-bit to bring them back together
	last_permute = ["0" for i in range(4)]
	last_permute[0] = left_2_bit[1]
	last_permute[1] = right_2_bit[1]
	last_permute[2] = right_2_bit[0]
	last_permute[3] = left_2_bit[0]
	result = "" # the final 4 bits
	for i in range(len(last_permute)):
		result += last_permute[i]

	return "{:04b}".format(int(result,2))

def inverse_initial_perm(almost_cp1, almost_cp2):
	# this takes two 4 bit strings, combines into an 8-bit string that's been DES'd twice and
	# applies a permutation to it:
	# 4 1 3 5 7 2 8 6
	# almost_cp1 is 1, 2, 3, 4 and almost_cp2 maps to 5, 6, 7, 8
	permute_list = ["0" for i in range(8)]
	permute_list[0] = almost_cp1[3]
	permute_list[1] = almost_cp1[0]
	permute_list[2] = almost_cp1[2]
	permute_list[3] = almost_cp2[0]
	permute_list[4] = almost_cp2[2]
	permute_list[5] = almost_cp1[1]
	permute_list[6] = almost_cp2[3]
	permute_list[7] = almost_cp2[1]
	result = ""
	for i in range(len(permute_list)):
		result += permute_list[i]
	return "{:08b}".format(int(result,2))

def encryptor(first_pt, K1, K2):
	# this is the overall function that generates the ciphertext
	# the first_pt is a little misleading but it's just the plaintext
	# security through obscurity?
	# L and R don't mean Left and right later in the cipher,
	# the number is just their state in each stage of the feistel
	IP = plain_text_IP(first_pt)
	L1, R1 = split_pt(IP)
	changed_R1 = F_function(R1, K1)
	# what is it XOR'd with? Itself? the other thing?
	xor_L1 = xor_4_bit_strings(L1, changed_R1)
	# for simplicity's sake
	R2 = xor_L1 # WAS JUST XOR'D
	L2 = R1
	changed_R2 = F_function(R2, K2)
	xor_R2 = xor_4_bit_strings(L2, changed_R2)
	cipher = inverse_initial_perm(xor_R2, R2)
	return "{:08b}".format(int(cipher, 2))

# the decryption piece, should mirror encryptor
def decryptor(first_ct, K1, K2):
	# again, this is just from slide 74.
	# same thing as above just a reverse of K1, K2
	# the first_ct is kind of misleading but
	# it's just the ciphertext
	# the ct has to be given in binary for this to work
	IP = plain_text_IP(first_ct)
	L1, R1 = split_pt(IP)
	changed_R1 = F_function(R1, K2)
	# what is it XOR'd with? Itself? the other thing?
	xor_L1 = xor_4_bit_strings(L1, changed_R1)
	# for simplicity's sake
	R2 = xor_L1 # WAS JUST XOR'D
	L2 = R1
	changed_R2 = F_function(R2, K1)
	xor_R2 = xor_4_bit_strings(L2, changed_R2)
	plaintext = inverse_initial_perm(xor_R2, R2)
	return "{:08b}".format(int(plaintext, 2))

# Functions for the thing
def encrypt(key, secret):
	# this is to make the implementation a little simpler
	# for the project
	secret_bin = text_to_bits(secret)
	block_list = []
	block = ""
	# print(len(secret_bin))
	for i in range(0, len(secret_bin), 8):
		for j in range(i, i+8):
			# print(j)
			block += secret_bin[j]
		block_list.append(block)
		block = ""


	# Over here, just make a bunch of keys based on 160 bits
	list_of_keys = []
	for i in range(0, 160, 10):
		list_k = ""
		for j in range(i, i+10):
			list_k+= key[j]
		list_of_keys.append(list_k)
		list_k = ""

	list_of_key_pairs = []
	for k in list_of_keys:
		realK1, realK2 = key_getter(k)
		list_of_key_pairs.append((realK1, realK2))

	# print(len(list_of_key_pairs))
	# print(len(block_list))

	# random.shuffle(list_of_key_pairs)

	encrypt_list = []
	encrypt_s = ""
	counter = 0
	for i in range(len(block_list)):
		if counter == len(list_of_key_pairs):
			counter = 0
		encrypt_list.append(encryptor(block_list[i], list_of_key_pairs[counter][0], list_of_key_pairs[counter][1]))
		counter += 1

	for i in range(len(encrypt_list)):
		encrypt_s += text_from_bits(encrypt_list[i])

	# print("The encrypted string is:", encrypt_s)

	return encrypt_s

def decrypt(key, message):
	decrypt_list = []
	encrypt_bits = text_to_bits(message)

	block = "" # this part breaks the encrypted message into 8 bit chunks
	for i in range(0, len(encrypt_bits), 8):
		for j in range(i, i+8):
			# print(j)
			block += encrypt_bits[j]
		decrypt_list.append(block)
		block = ""

	list_of_keys = []
	for i in range(0, 160, 10):
		list_k = ""
		for j in range(i, i+10):
			list_k+= key[j]
		list_of_keys.append(list_k)
		list_k = ""

	key_pairs = []
	for k in list_of_keys:
		realK1, realK2 = key_getter(k)
		key_pairs.append((realK1, realK2))

	# this block will decrypt the blocks and turn them into binary
	decrypt_bits = []
	counter = 0
	for i in range(len(decrypt_list)):
		if counter == len(key_pairs):
			counter = 0
		decrypt_bits.append(decryptor(decrypt_list[i], key_pairs[counter][0], key_pairs[counter][1]))
		counter += 1

	# finally, we convert the bits to something readable.
	block = ""
	for i in range(len(decrypt_bits)):
		block += text_from_bits(decrypt_bits[i])

	# print("The decrpyted string is:",block)

	return block

	# NOW FOR THE 3DES FUNCTIONS!!! Based on this wiki: https://en.wikipedia.org/wiki/Triple_DES

def key_maker_3(key):
	k1_3 = key
	k2_3 = k1_3[::-1]
	mid = len(k2_3)//2
	k3_3 = ['0' for i in range(len(k2_3))]
	for i in range(mid, len(k2_3)):
		k3_3[i] = k2_3[i]
	for i in range(mid):
		k3_3[i] = k1_3[i]
	k3_3 = "".join(k3_3)
	#print("lens:", len(k1_3),len(k2_3),len(k3_3))
	assert len(k1_3) == 160
	assert len(k2_3) == 160
	assert len(k3_3) == 160
	return k1_3, k2_3, k3_3

def encrypt3(key, secret):
	k1, k2, k3 = key_maker_3(key)
	first_part = encrypt(k1, secret)
	second_part = decrypt(k2, first_part)
	encrypt_s3 = encrypt(k3, second_part)

	return encrypt_s3

def decrypt3(key, secret):
	k1, k2, k3 = key_maker_3(key)
	first_d = decrypt(k3, secret)
	second_d = encrypt(k2, first_d)
	decrypt3 = decrypt(k1, second_d)

	return decrypt3


if __name__ == "__main__":
	# TCP or UDP, your choice
	# print(sys.argv[2])
	# print(len(sys.argv[2]))
	if len(sys.argv)!= 3 or len(sys.argv[2]) != 160:
		print("Usage: toy_des.py <string to encrypt> <key> and key should be 160 bits") # key is just 10 of 0 or 1
		exit()

	secret = sys.argv[1]
	key = sys.argv[2]
	print("You would like to encrypt:", secret)

	# converting to a binary representation
	# was using credits to https://stackoverflow.com/questions/18815820/convert-string-to-binary-in-python, not anymore

	msg= encrypt(key, secret)

	msg2 = decrypt(key, msg)

	print("\nNOW FOR 3DES\n")

	key1_3, key2_3, key3_3 = key_maker_3(key)
	print("k1_3: ", key1_3)
	print("k2_3: ",key2_3)
	print("k3_3: ",key3_3)

	triple_e = encrypt3(key, secret)
	print("The encrypted string with triple DES is:", triple_e)
	decrypt3_d = decrypt3(key, triple_e)
	print("The decrpyted string with triple DES is:", decrypt3_d)
