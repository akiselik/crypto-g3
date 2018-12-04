import  socket, secrets, sys
from random import randrange, getrandbits
import rsa, verify, bg, des3 as des

def genP(length):
    """ Generate an odd integer randomly
        Args:
            length -- int -- the length of the number to generate, in bits
        return a integer
    """
    # generate random bits
    p = secrets.randbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p
def isPrime(n):
	if n == 2:
		return True
	if n < 2 or n % 2 == 0:
		return False
	for i in range(3, int(n**0.5)+2, 2):
		if n % i == 0:
			return False
	return True

def gp(len):
    if(len<2):
        return None
    a = genP(len)
    while(isPrime(a) == False or a%4 != 3):
        a = genP(len)
    return(a)

def encrypt(algo, message, p, q):
    n = p*q
    key = "{:0160b}".format(n)
    hm = verify.hmac(n, message)
    fullmsg = message + hm
    if(algo == 0):
        return(bg.encrypt(fullmsg, n))
    if(algo == 1):
        return(des.encrypt3(key, fullmsg))

def decrypt(algo, message, p, q):
    n = p*q
    key = "{:0160b}".format(n)
    if(algo == 0):
        msg = bg.decrypt(message, p, q)
    if(algo == 1):
        msg = des.decrypt3(key, message)
    retmsg = msg[:-40]
    hm = msg[-40:]
    return retmsg, hm

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 9898
soc.connect((host, port))

hello = "Client Hello%" + str(secrets.randbelow(2048)) + "%Blum-Goldwasser;3DES"
soc.sendall(hello.encode('utf-8')), "hello"
servHello = soc.recv(1024)
servHello = servHello.decode('utf-8')
sh = servHello.split("%")
protocol = int(sh[1])
cert = sh[3]
p = gp(55)
q = gp(53)
msg = str(p)+"%"+str(q)
cert = cert.replace('(','')
cert = cert.replace(')','')
cert = cert.replace(' ','')
cert = cert.split(",")
cert = list(map(int, cert))
msg = rsa.encrypt(cert, msg)
soc.sendall(str(msg).encode('utf-8'))
key = p*q
key = "{:0160b}".format(key)
msg = "changecipherspec"
#ADD verify.hmac
hm = verify.hmac(p*q, msg)
msg = msg+hm
soc.sendall(msg.encode('utf-8'))
data = soc.recv(15360)
data = data.decode('utf-8')
msg, hm = decrypt(protocol, data, p, q)
vhm = verify.hmac(p*q, msg)
if(hm != vhm):
    print("verify.hmac not equivilient - quitting")
    soc.close()
    quit()
#verify verify.hmac
#SECURE CONNECTION ESTABLISHED
print("Secure Connection Established...Chat Server Staring...")
while True:
    msg = ""
    tosend = input("Send a message (quit to stop): ")
    send = encrypt(protocol, tosend, p, q)
    soc.sendall(send.encode('utf-8'))
    if(tosend == "quit"):
        print("QUITTING.....")
        break

    data = soc.recv(15360)
    data = data.decode('utf-8')
    msg, hm = decrypt(protocol, data, p, q)
    vhm = verify.hmac(p*q, msg)
    if(hm != vhm):
        print("verify.hmac not equivilient - quitting")
        soc.close()
        quit()
    if(msg == "quit"):
        print("QUITTING.....")
        break
    print("INCOMING MESSAGE: ",msg)
soc.close()
