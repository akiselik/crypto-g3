# crypto-g3

To run the project:

Use Python 3.7.1

First run server.py
Then run client.py

The program will start, however, it will take time before you can interact with it as it is generating large prime numbers.

Upon the generation of the prime numbers, the client and server will agree upon Public Key Cryptosystems and connect to each other in a manner as described by SSH/SSL standards. This connection will be done automatically. Once they are connected, the client and server can securely send messages to each other.

Files:
- bg.py -- blum-goldwasser implementation
- rsa.py -- rsa implementation
- sha1_hex.py -- sha1 implementation
- verify.py -- hmac implementation
- des_160b.py -- 3DES implementation
- server.py -- server
- client.py -- client
