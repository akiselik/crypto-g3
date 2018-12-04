import math, secrets

def text_to_bits(cti):
    return ''.join('{:08b}'.format(ord(c)) for c in cti)

def text_from_bits(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))

def gcd(a, b): #return (g, x, y) a*x + b*y = gcd(x, y) = g
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = gcd(b%a, a)
		return(g, x - (b // a) * y, y)

def encrypt(m, n):
    r = secrets.randbelow(n-1) + 1
    X0 = pow(r,2,n)
    k = math.floor(math.log(n,2))
    h = math.floor(math.log(k,2))
    m = text_to_bits(m)
    msg = []
    t = len(m)//h
    if(t<len(m)/h):
        t+=1
    xi = X0
    c = []
    for i in range(t):
        mi = m[i*h:(i + 1)*h]
        for i in range(h-len(mi)):
            mi+='0'
        xi = pow(xi,2,n)
        xi_bin = bin(xi)
        pi = xi_bin[-h:]

        mi_int = int(mi, 2)
        pi_int = int(pi, 2)

        ci = pi_int ^ mi_int
        ci_bin = format(ci, '0' + str(h) + 'b')
        c += ci_bin
    c.append(pow(xi,2,n))
    c = list(map(int, c))
    return(str(c))

def decrypt(c, p, q):
    c = c.replace("[", '')
    c = c.replace("]", '')
    c = c.replace(" ", '')
    c = c.split(",")
    c = list(map(int, c))
    ct = c[-1]
    c = c[:-1]
    n = p*q
    k = math.floor(math.log(n,2))
    h = math.floor(math.log(k,2))
    t = len(c)//h
    if(t<len(c)/h):
        t+=1
    g, a, b = gcd(p,q)
    d1 = pow((p+1)//4, t+1, p-1)
    d2 = pow((q+1)//4, t+1, q-1)
    u = pow(ct, d1, p)
    v = pow(ct, d2, q)
    x0 = (v*a*p + u*b*q) % n
    xi = x0
    m = ""
    for i in range(t):
        ci = c[i*h:(i + 1)*h]
        xi = pow(xi,2,n)
        xi_bin = bin(xi)
        pi = xi_bin[-h:]
        ci = ''.join(str(x) for x in ci)
        ci_int = int(ci, 2)
        pi_int = int(pi, 2)

        mi = pi_int ^ ci_int
        mi_bin = format(mi, '0' + str(h) + 'b')
        m += mi_bin
    return text_from_bits(m)
