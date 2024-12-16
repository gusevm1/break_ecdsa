import json
import logging
import sys
import os
import socket

from ecdsa2 import ECDSA2, ECDSA2_Params, Point, bits_to_int, hash_message_to_bits
from sage.all import Zmod, Integer

# Change the port to match the challenge you're solving
PORT = 40110

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

# ECDSA² parameters for P-256
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

params = ECDSA2_Params(a, b, p, P_x, P_y, q)
ecdsa2 = ECDSA2(params)





# let's now solve the equation for x (the secret key)
# s = k^-1 (h^2 + 1337 x r ) mod q
# <==> s * k = h^2 + 1337 x r mod q
# <==> s * k - h^2 = 1337 x r mod q
# <==> x = (s * k - h^2) (1337* r)^-1 mod q

json_send({"command": "get_signature", "msg": "Now you're just some value that I used to nonce"})
response = json_recv()
#print(response)
s = response["s"]
r = response["r"]

# calculate h and k
h = bits_to_int(hash_message_to_bits("Now you're just some value that I used to nonce"), q)
k = ecdsa2.Z_q(h)


s = ecdsa2.Z_q(s)
r = ecdsa2.Z_q(r)

r_1337 = (1337 * r)
r_1337_inv = 1 / r_1337


x = ((int(s) * int(k) - int(h) * int(h)) * int(r_1337_inv)) % q
x = ecdsa2.Z_q(x)
#print(f"calculated x: {x}")

# hehe yeee boy its time to cook
r, s = ecdsa2.Sign_FixedNonce(k, x, "gimme the flag")

json_send({"command": "solve", "r": int(r), "s": int(s)})
response = json_recv()
flag = response["flag"]
print(flag)






