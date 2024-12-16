import json
import logging
import sys
import os
import socket

import time

from ecdsa2 import ECDSA2, ECDSA2_Params, Point, bits_to_int, hash_message_to_bits
from sage.all import Zmod, Integer

import hashlib
from itertools import product

# Change the port to match the challenge you're solving
PORT = 40120

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


base_time = int(time.time()) #time step used on the server meaning we manage to recover ts like this
base_time = str(base_time)
#print(base_time)
#print(len(base_time)) # 10 digits



json_send({"command": "get_signature", "msg": "burner1"})

response = json_recv()
#print(response)
r1 = response["r"] # recover signature of r and s for the burner message
s1 = response["s"]

s1 = ecdsa2.Z_q(s1)
r1 = ecdsa2.Z_q(r1)

json_send({"command": "get_signature", "msg": "burner2"})
response = json_recv()
#print(response)
r2 = response["r"]
s2 = response["s"]

s2 = ecdsa2.Z_q(s2)
r2 = ecdsa2.Z_q(r2)

#print(f"r1: {r1}, r2: {r2}, s1: {s1}, s2: {s2}")

# recovered s1 and s2 and r1 and r2
# s1 = k^-1(h(burner1)^2 + 1337 * r1 * x) mod q
# s2 = k^-1(h(burner2)^2 + 1337 * r2 * x) mod q
# s1 - s2 = k^-1(h(burner1)^2 - h(burner2)^2 + 1337 * r1 * x - 1337 * r2 * x) mod q      | r1 = r2
# s1 - s2 = k^-1(h(burner1)^2 - h(burner2)^2) mod q
# k = (s1 - s2)^-1(h(burner1)^2 - h(burner2)^2) mod q

h1 = bits_to_int(hash_message_to_bits("burner1"), q)
h2 = bits_to_int(hash_message_to_bits("burner2"), q)

h1_squared = h1 * h1
h2_squared = h2 * h2

s1_minus_s2 = s1 - s2
inv_s1_minus_s2 = 1/s1_minus_s2
#print(f"inv_s1_minus_s2: {inv_s1_minus_s2}")

k = inv_s1_minus_s2 * (h1_squared - h2_squared)
#print(f"k: {k}")

# we now recovered k! we can use the exact same attack as last time now

s1 = ecdsa2.Z_q(s1)
r1 = ecdsa2.Z_q(r1)

r_1337 = (1337 * r1)
r_1337_inv = 1 / r_1337


x = ((int(s1) * int(k) - int(h1) * int(h1)) * int(r_1337_inv)) % q
x = ecdsa2.Z_q(x)

#print(f"calculated x: {x}")
# hehe yeee boy its time to cook
r, s = ecdsa2.Sign_FixedNonce(k, x, "gimme the flag")

json_send({"command": "solve", "r": int(r), "s": int(s)})
response = json_recv()
flag = response["flag"]
print(flag)