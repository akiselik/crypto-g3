###rsa implementation

import random

## (https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm)
## Euclid's GCD and Extended algorithms
def gcd(a, b): #return (g, x, y) a*x + b*y = gcd(x, y) = g
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = gcd(b%a, a)
		return(g, x - (b // a) * y, y)

##Euclid's extended algorithm
def multInv(e, phi):
	g, x, y = gcd(e, phi)
	if g!=1:
		raise Exception('multiplicative inverse does not exist')
	else:
		return x % phi

##primality testing
def isPrime(n):
	if n == 2:
		return True
	if n < 2 or n % 2 == 0:
		return False
	for i in range(3, int(n**0.5)+2, 2):
		if n % i == 0:
			return False
	return True

##key generation
def keyGen(p, q):
	if not(isPrime(p) and isPrime(q)):
		raise ValueError('Both numbers must be prime.')
	elif p == q:
		raise ValueError('p and q cannot be equal')
	#n = p*q
	n = p*q

	#phi is Euler's totient function of n
	phi = (p-1) * (q-1)

	#we need an encryption exponent e such that gcd(e, phi(n))=1
	e = random.randrange(1, phi)

	#verify coprimality of e, phi(n)
	g, x, y = gcd(e, phi)
	while g != 1:
		e = random.randrange(1, phi)
		g, x, y = gcd(e, phi)

	#generate decryption exponent d = e^(-1) mod phi(n)
	d = multInv(e, phi)

	#return public (e, n), private (d,p,q) keypair
	return ((e, n), (d, p, q))

##encryption
def encrypt(k, plaintext):
	#k = (e, n)
	key, n = k

	#convert each letter
	cipher = [pow(ord(char),key,n) for char in plaintext]
	#return the byte array
	return cipher

def decrypt(k, ciphertext):
	#k = (d, p, q)
	key, p, q = k
	n = p*q
	plain = [chr(pow(char, key, n)) for char in ciphertext]

	#return byte array as a string
	return ''.join(plain)

if __name__ == '__main__':
	print("RSA En/Decrypter")
	p = int(input("Enter a prime number: "))
	q = int(input("Enter another prime number: "))
	print("generating public/private keypairs...")
	public, private = keyGen(p, q)
	print("your public key is ", public," and your private key is ", private)
	msg = input("Enter a message to encrypt: ")
	ctxt = encrypt(public, msg)
	print("your encrypted message is: ", ''.join(map(lambda x: str(x), ctxt)))
	print("decrypting message with private key: ", decrypt(private, ctxt))
	print("done")
