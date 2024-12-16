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
PORT = 40320

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

a   = 17
b   = 1
n   = 0x579d4e9590eeb88fd1b640a4d78fcf02bd5c375351cade76b69561d9922d3070d479a67192c67265cf9ae4a1efde400ed40757b0efd2912cbda49e60c83a1ddd361d31859bc4e206158491a528bd46d0b41c6e8d608c586a0788b8027f0f796e9e077766f83683fd52965101bb7bf9fd90c9e9653f02fada8bf10d62bc325ef
P_x = 0x54d73da0d9a78dc3a7914c1677def57a6f4e74c424e574f93e5252885833f988e27517b5b4da981dd69fc242d5c0dc3d17e6129c6e4af4cd2cfb8200ce49c17381d80e2dd9e3d5f0517e720a7db3d903ca11b33069edffbba39f71f6b5f8d698ab1a8170017ed6d1675175e6e54b6ebbb94da460d623b87669c8686d2d4b856
P_y = 0x30ba788b53a932136fdfdd0f82d6328a1bbb29368aa22d8fe2c2ae16a7d466f1a8d0e4b0fe725ed049c9ae41090e521add6e7e1d5f7f498942bae2a997f2f55bdd7959f5d72c3d781d657cb0feb81e7e15fd7065b3ce6f5b5cd5218e8c101841e600c1920d4e8fb3dd3aaf2458861015f652babcd32be90f46a8cdbc54edd1
curve = EllipticCurve(Zmod(n), [a, b])

json_send({"command": "get_ciphertext"})
response = json_recv()
# print(response)
eph_x = response["eph_x"]
eph_y = response["eph_y"]
ciphertext = response["ciphertext"]

# Convert to binary string in 8-bit chunks
binary_representation = ""
for i in range(0, len(ciphertext), 2):
    # convert it to bytes
    byte = int(ciphertext[i:i+2], 16)
    byte = format(byte, '08b')
    binary_representation += byte
    
# convert the binary string to a bytestring
byte_representation = int(binary_representation, 2).to_bytes(len(binary_representation) // 8, byteorder='big')# Convert to binary string in 8-bit chunks
binary_representation = ""
for i in range(0, len(ciphertext), 2):
    # convert it to bytes
    byte = int(ciphertext[i:i+2], 16)
    byte = format(byte, '08b')
    binary_representation += byte
    
# convert the binary string to a bytestring
byte_representation = int(binary_representation, 2).to_bytes(len(binary_representation) // 8, byteorder='big')
# print(byte_representation)


leak = int.from_bytes(byte_representation[16:128]) 

y = int.from_bytes(byte_representation[128:]) 
xor = byte_representation[:16] 
X= 2**128
x_offset = 2**896
xor = int.from_bytes(xor)

f0 = leak**3 + a*leak + b - y**2
f1 = 3*leak**2*x_offset + a*x_offset
f2 = 3*leak*x_offset**2 
f3 = x_offset**3

Zn = Zmod(n)
f3, f2, f1, f0 = Zn(f3), Zn(f2), Zn(f1), Zn(f0)
f3_inv = 1 / f3
f3_prime, f2_prime, f1_prime, f0_prime = f3 * f3_inv, f2 * f3_inv, f1 * f3_inv, f0 * f3_inv

polynomial_coeffs = [int(f0_prime), int(f1_prime), int(f2_prime), int(f3_prime)]

def build_copper_smith_lattice(polynomial_coeffs, M, X):
    d = 3 # it's a d+1 x d+1 matrix
    rows = []
    last_row = []
    for i in range(d) : # entires
        row = [0] * (d + 1)
        row[i] = M * X ** i 
        rows.append(row)
        last_row.append(polynomial_coeffs[i] * X ** i)
    
    last_row.append(polynomial_coeffs[-1] * X ** d) # entry in (d+1, d+1), coeff[-1] = 1
    rows.append(last_row)

    copper_smith_lattice = matrix(ZZ, rows)
    return copper_smith_lattice



copper_smith_lattice = build_copper_smith_lattice(polynomial_coeffs, n, X)
# print(copper_smith_lattice)

reduced_matrix = copper_smith_lattice.LLL()

poly_coeffs = reduced_matrix[0]
poly_coeffs = [c / X**i for i, c in enumerate(poly_coeffs)]

x = PolynomialRing(ZZ, 'x').gen()
G_x = sum(c * x**i for i, c in enumerate(poly_coeffs))
roots = G_x.roots()
# print(roots)
root = roots[0][0]
root = int(root)

secret = (xor ^ root).to_bytes(16, byteorder='big')

json_send({"command": "solve", "plaintext": secret.decode()})
response = json_recv()
print(response["flag"])

# F(x) = x^3 + a*x + b - y^2 = k^3 + 3*leak*x_offset*k^2 + 3*leak^2 + a 




