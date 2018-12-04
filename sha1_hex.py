##sha-1
##(https://modernresearchconsulting.com/2017/07/23/implementing-sha-1-in-python/)

# h0 = 0x67452301
# h1 = 0xEFCDAB89
# h2 = 0x98BADCFE
# h3 = 0x10325476
# h4 = 0xC3D2E1F0

#m1 = msg length in bits

def ROTL(x, n, w):
	return((x << n & (2**w-1)) | (x >> w - n))

def Ch(x, y, z):
	# #print("x[",x,"]","y[",y,"]","z[",z,"]",)
	return((x & y) ^ (~x & z))

def Parity(x, y, z):
	return(x ^ y ^ z)

def Maj(x, y, z):
	return((x & y) ^ (x & z) ^ (y & z))

def divideString(string, n):
	str_size = len(string)
	if str_size % n != 0:
		#print("String size is not divisible by ", n)
		return
	part_size = int(str_size/n)
	output = list(map(''.join, zip(*[iter(string)]*part_size)))
	return output

def sha1(x):
	K = []

	for t in range(80):
		if t <= 19:
			K.append(0x5a827999)
		elif t <= 39:
			K.append(0x6ed9eba1)
		elif t <= 59:
			K.append(0x8f1bbcdc)
		else:
			K.append(0xca62c1d6)

	x_bytes = bytearray(x, 'ascii')
	x_bits = [format(x, '08b') for x in x_bytes]
	x_bitlength = len(x_bits[0])
	#print('x_bitlength: ', x_bitlength)
	#print('x_bits: ', x_bits)
	x_bits_string = ''.join(x_bits)
	#print('x_bits_string: ', x_bits_string)
	# k = (512 + 448 - ((x_bitlength % 512))+1) % 512
	k = (((447 - (len(x)*x_bitlength)) % 512) + 512) % 512
	#print('k: ', k)
	pad_bits = '1' + ('0' * k) + format(len(x) * x_bitlength, '064b')
	# pad_bits = '1' + ('0' * (448 - (8 * len(x) + 1))) + format(len(x) * 8, '064b')
	x_padded = x_bits_string + pad_bits
	#print('x_padded: ', x_padded)
	#print('len(x_padded): ', len(x_padded))
	assert(len(x_padded) % 512 == 0)

	#M_1, M_2, ..., M_N where N=len(x_padded)/512
	#M1 = x_padded
	H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
	# Hint = [int(h,16) for h in H]
	N = int(len(x_padded)/512)
	#print('N: ', N)
	Mblocks = divideString(x_padded, N)
	#print('Mblocks: ', Mblocks)

	for i in range(1, N+1):
		M_i = Mblocks[i-1]
		#print('------' * 2)
		#print('i = ', i)
		W = list()
		for t in range(80):
			if t <= 15:
				W.extend([ int(M_i[ (32*t) : (32 * (t+1)) ], 2)])
			else:
				W.extend([ ROTL( W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], n=1, w=32) ])
		#print('W: ', W[0:16])
		#print('H: ', H)

		a = H[0]
		b = H[1]
		c = H[2]
		d = H[3]
		e = H[4]

		for t in range(80):
			if t <= 19:
				f = Ch
			elif t <= 39:
				f = Parity
			elif t <= 59:
				f = Maj
			else:
				f = Parity

			##print(type, everything please)
			T = (ROTL(a, n=5, w=32) + f(b, c, d) + e + K[t] + W[t]) % (2 ** 32)
			e = d
			d = c
			c = ROTL(b, n=30, w=32)
			b = a
			a = T

		H[0] = (a + H[0]) % (2 ** 32)
		H[1] = (b + H[1]) % (2 ** 32)
		H[2] = (c + H[2]) % (2 ** 32)
		H[3] = (d + H[3]) % (2 ** 32)
		H[4] = (e + H[4]) % (2 ** 32)

	H = [format(x, '08x') for x in H]
	return(''.join(H))

if __name__ == '__main__':
	print("SHA-1")
	x = input("Enter a message to hash using SHA-1: ")
	print('output: ', sha1(x))
