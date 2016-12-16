import sys
import socket
import select
import hashlib
import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from Crypto import Random
import time
import datetime
import ast
import os
import pickle
import threading
from random import randint

f1 = open("client_list_server.txt", 'a+')


def global_print(*names):
    x = lambda s: ["{}", "0x{:x}"] [hasattr(s, 'real')].format(s)
    print("".join("{} = {}\n".format(name, x(globals()[name])) for name in names))


def H(*args):  
    a = ':'.join(str(a) for a in args)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(a)
    hash_of_message = digest.finalize()
    return int(hash_of_message.encode('hex'), 16)
    

def cryptrand(n=2048):
    return random.SystemRandom().getrandbits(n) % N

N = '''00:c0:37:c3:75:88:b4:32:98:87:e6:1c:2d:a3:32:
       4b:1b:a4:b8:1a:63:f9:74:8f:ed:2d:8a:41:0c:2f:
       c2:1b:12:32:f0:d3:bf:a0:24:27:6c:fd:88:44:81:
       97:aa:e4:86:a6:3b:fc:a7:b8:bf:77:54:df:b3:27:
       c7:20:1f:6f:d1:7f:d7:fd:74:15:8b:d3:1c:e7:72:
       c9:f5:f8:ab:58:45:48:a9:9a:75:9b:5a:2c:05:32:
       16:2b:7b:62:18:e8:f1:42:bc:e2:c3:0d:77:84:68:
       9a:48:3e:09:5e:70:16:18:43:79:13:a8:c3:9c:3d:
       d0:d4:ca:3c:50:0b:88:5f:e3'''
N = int(''.join(N.split()).replace(':', ''), 16)
g = 2        

k = H(N, g)  







I = sys.argv[1]       
p = sys.argv[2]  
s = cryptrand(64)
x = H(s, I, p)   
v = pow(g, x, N) 




f1.write(I)
f1.write("**********")
f1.write(str(s))
f1.write("**********")
f1.write(str(v))
f1.write("**********")
f1.write(str(k))
f1.write("**********")
f1.write(str(N))
f1.write("**********")
f1.write(str(g))
f1.write("\n")
f1.flush()
f1.close()



a = cryptrand()
A = pow(g, a, N)



b = cryptrand()
B = (k * v + pow(g, b, N)) % N



u = H(A, B) 




x = H(s, I, p)
S_c = pow(B - k * pow(g, x, N), a + u * x, N)
K_c = H(S_c)



S_s = pow(A * pow(v, u, N), b, N)
K_s = H(S_s)



M_c = H(H(N) ^ H(g), H(I), s, A, B, K_c)




M_s = H(A, M_c, K_s)


