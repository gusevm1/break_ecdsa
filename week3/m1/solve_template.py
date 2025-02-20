import json
import logging
import sys
import os
import socket

from sage.all import matrix, vector
from sage.all import *
from sage.all import Zmod

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


# Change the port to match the challenge you're solving
PORT = 40310

# Pro tip: for debugging, set the level to logging.DEBUG if you want
# to read all the messages back and forth from the server
# log_level = logging.DEBUG
log_level = logging.INFO
logging.basicConfig(stream=sys.stdout, level=log_level)

s = socket.socket()

# Set the environmental variable REMOTE to True in order to connect to the server
#
# To do so, run on the terminal:
# REMOTE=True sage solve.py
#
# When we grade, we will automatically set this for you
if "REMOTE" in os.environ:
    s.connect(("isl.aclabs.ethz.ch", PORT))
else:
    s.connect(("localhost", PORT))

fd = s.makefile("rw")


def json_recv():
    """Receive a serialized json object from the server and deserialize it"""

    line = fd.readline()
    logging.debug(f"Recv: {line}")
    return json.loads(line)

def json_send(obj):
    """Convert the object to json and send to the server"""

    request = json.dumps(obj)
    logging.debug(f"Send: {request}")
    fd.write(request + "\n")
    fd.flush()

# WRITE YOUR SOLUTION HERE

# This file only contains code written by me.

keysize = 2048
# p is half of the keysize, and 3/4 will be leaked, while 1/4 remains encrypted
p_bits = keysize // 2
nonleaked_bits = p_bits // 4
leaked_bits = p_bits - nonleaked_bits
X = 2 ** nonleaked_bits
x_scale = 2 ** leaked_bits

for n in (keysize // 4, keysize):
    json_send({ "command": "gen_key", "bit_length": n, "identifier": "id" })
    json_recv()

json_send({ "command": "get_pubkey", "identifier": "id" })
pubkey = json_recv()
N = pubkey["n"]
e = pubkey["e"]

json_send({ "command": "export_p", "identifier": "id" })
res = json_recv()
obfuscated_p = bytearray.fromhex(res["obfuscated_p"])

# now it's just coppersmith... (following example 19.4.3)

leaked_bytes = obfuscated_p[nonleaked_bits:]
leaked_p = int(leaked_bytes, 2)
x = Zmod(N)['x'].gen()
# x has to be multiplied by x_scale because x's bits are the MSB
F_x = leaked_p + x * x_scale
F_x = F_x.monic().change_ring(ZZ)
# take the monic p value
p = F_x[0]

B = matrix(ZZ, 4, 4)

B[0, 0] = N
for i in range(1, 4):
    B[i, i] = X ** i

for i in range(1, 4):
    B[i, i-1] = p * X ** (i - 1)

B = B.LLL()

x = ZZ['x'].gen()
# from https://ask.sagemath.org/question/10734/polynomial-coefficient-vector-to-symbolic-polynomial/
G_x = sum([(b / X ** a) * x ** a for a,b in enumerate(B.rows()[0])])

roots = G_x.roots()
roots = list(map(lambda x: int(x[0]), roots))

for root in roots:
    print("Trying root", root)
    p = int(leaked_p + root * x_scale)
    # reverse the key generation
    q = N // p
    phi = (p-1) * (q-1)
    Zphi = Zmod(phi)
    d = 1/Zphi(e)

    h = int.from_bytes(SHA256.new(b"gimme the flag").digest())
    Zn = Zmod(N)
    signature = Zn(h) ** d

    json_send({ "command": "solve", "identifier": "id", "signature": int(signature) })
    res = json_recv()
    if "flag" in res:
        print(res["flag"])
        break

