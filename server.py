#connect to server
#receive client hello, random var, supported cipher suites
#send server hello, chosen protocol, random var, certificate aka public key, server hello done
#receive prime p, generator g encrypted with the servers public key
#computational diffie hellman
#receive change cipher spec w/ verify.hmac
#send change cipher spec & server finished using newly agreed upon key & verify.hmac

import socket, time, secrets, sys, random
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(('localhost', 9898))
serversocket.listen(1)
sys.path.append("../")
import rsa, des_160b as des, bg, verify


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
        return(des.encrypt(key, fullmsg))

def decrypt(algo, message, p, q):
    n = p*q
    key = "{:0160b}".format(n)
    if(algo == 0):
        msg = bg.decrypt(message, p, q)
    if(algo == 1):
        msg = des.decrypt(key, fullmsg)
    retmsg = msg[:-40]
    hm = msg[-40:]
    return retmsg, hm

p = gp(20)
q = gp(20)
while(q == p):
    q = gp(20)

public, private = rsa.keyGen(p, q)


while True:
    connection, address = serversocket.accept()
    ip, port = str(address[0]), str(address[1])
    print("Connected with " + ip + ":" + port)
    hello = connection.recv(1024)
    hello = hello.decode('utf-8')
    hello = hello.split('%')
    algo = hello[2].split(";")
    chosen = secrets.randbelow(len(algo))
    #chosen = 0 #THIS WILL PREVENT THE ALGORITHM FROM BEING RANDOMLY CHOSEN 0 = BG 1 = DES
    cert = public
    msg = "server hello%" + str(chosen) +"%"+ str(secrets.randbelow(2048)) +"%"+ str(cert)+"%server hello done"
    connection.sendall(msg.encode('utf-8'))
    data = connection.recv(4096)
    data1 = data.decode('utf-8')
    data2 = data1.replace("[", '')
    data3 = data2.replace("]", '')
    data4 = data3.split(", ")
    data5 = list(map(int, data4))
    rsaDec = rsa.decrypt(private, data5)
    pga = rsaDec.split("%")
    p = int(pga[0])
    q = int(pga[1])
    key = p*q
    key = "{:0160b}".format(key)
    data = connection.recv(1024)
    data = data.decode('utf-8')
    #VERYIFY verify.hmac
    m = data[:-40]
    h = data[-40:]
    vh = verify.hmac(p*q, m)
    if(h != vh):
        print("verify.hmac not the same- quitting")
        connection.close()
        serversocket.close()
        quit()
    msg = "changecipherspec"
    send = encrypt(chosen, msg, p, q)
    #encrypt & add verify.hmac
    connection.sendall(send.encode('utf-8'))
    #SECURE CONNECTION ESTABLISH
    print("Secure Connection Established...Chat Server Staring...Waiting for Incoming Message...")
    while True:
        msg = ""
        data = connection.recv(15360)
        data = data.decode('utf-8')
        msg, hm = decrypt(chosen, data, p, q)
        vhm = verify.hmac(p*q, msg)
        if(hm != vhm):
            print("verify.hmac not equivilient - quitting", p*q)
            connection.close()
            quit()
        if(msg == "quit"):
            print("QUITTING.....")
            break
        print("INCOMING MESSAGE: ",msg)

        tosend = input("Send a message (quit to stop): ")
        send = encrypt(chosen, tosend, p, q)
        connection.sendall(send.encode('utf-8'))
        if(tosend == "quit"):
            print("QUITTING.....")
            break

    connection.close()
    break
serversocket.close()
