import json
import logging
import sys
import os
import socket

from sage.all import matrix, vector
from sage.all import *

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

# we attack by overwriting existing values but bits stay 512

json_send({"command": "gen_key", "bit_length": 512, "identifier": "a"})
response = json_recv() # {'res': 'Succesfully new public key for identifier a'}

# we set identifier, p, q, n, e, d, bits

json_send({"command": "gen_key", "bit_length": 2048, "identifier": "a"})

# we set p, q, n, e, d with the new values... but not bits!
response = json_recv() # {'res': 'Succesfully new public key for identifier a'}

json_send({"command": "get_pubkey", "identifier": "a"})
response = json_recv() # {'n': 12346213846..1234124, 'e': 65537, 'bits': 512}
n = response["n"]
e = response["e"]
bits = response["bits"]
# print(response)

json_send({"command": "export_p", "identifier": "a"})
response = json_recv() # {'nonce': 3374583ddf6e5e13, obfuscated_p: abcd123bcadf3123...af6913030303131313130...}
nonce = response["nonce"]
obfuscated_p = response["obfuscated_p"]
# print(response)


# Convert to binary string in 8-bit chunks
binary_representation = ""
for i in range(0, len(obfuscated_p), 2):
    # convert it to bytes
    byte = int(obfuscated_p[i:i+2], 16)
    byte = format(byte, '08b')
    binary_representation += byte
    
# convert the binary string to a bytestring
byte_representation = int(binary_representation, 2).to_bytes(len(binary_representation) // 8, byteorder='big')
leak_of_byte_representation = byte_representation[256:]
p_ = int(leak_of_byte_representation, 2)


X = 2**256

# F(x) = p_ + a*x
# we want the matrix to be moenic in Zn
Zn = Zmod(n)
a = 2**768
p_, a = Zn(p_), Zn(a)
a_inv = 1 / a
a_prime, p_prime = a * a_inv, p_ * a_inv

a, a_prime, p_, p_prime = int(a), int(a_prime), int(p_), int(p_prime)


def build_copper_smith_lattice(p_prime, M, X):
    rows = []

    # First row
    rows.append([M, 0, 0, 0])

    # Remaining rows
    for i in range(1, 4):
        row = [0] * 4  # Initialize a row of zeros
        row[i - 1] = p_prime * X ** (i - 1)  # Set the value for the (i, i-1) entry
        row[i] = X ** i               # Set the value for the (i, i) entry
        rows.append(row)

    copper_smith_lattice = matrix(ZZ, rows)
    return copper_smith_lattice


copper_smith_lattice = build_copper_smith_lattice(p_prime, n, X)

reduced_matrix = copper_smith_lattice.LLL()

poly_coeffs = reduced_matrix[0]
poly_coeffs = [c / X**i for i, c in enumerate(poly_coeffs)]

x = PolynomialRing(ZZ, 'x').gen()


G_x = sum(c * x**i for i, c in enumerate(poly_coeffs))
roots = G_x.roots()
roots = [root[0] for root in roots]
root = roots[0]


p = int(p_ + root * a)
    
# server code
q = n // p
phi = (p-1) * (q-1)
Zphi = Zmod(phi)
d = 1/Zphi(e)

h = int.from_bytes(SHA256.new(b"gimme the flag").digest())
Zn = Zmod(n)
sign = Zn(h) ** d

json_send({ "command": "solve", "identifier": "a", "signature": int(sign) })
res = json_recv()
flag = res["flag"]
print(flag)





