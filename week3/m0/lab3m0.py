import json
import logging
import sys
import os
import socket

from sage.all import matrix, vector
from sage.all import *

# Change the port to match the challenge you're solving
PORT = 40300

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
json_send({"command" : "get_pubkey"})
response = json_recv()
n = response["n"]
e = response["e"]


json_send({"command" : "get_ciphertext", "message" : "test"})
response = json_recv()
ciphertext_hex = response["ciphertext"]
# Convert the bytes to an integer
c = int(ciphertext_hex, 16)


# padding
b = "01101111" * 111
b = int(b, 2)
a = 2**888
X = 2**128
M = n

# realize now that our secret is [\x00] + [secret_message] + [b]
f0 = b**3 - c
f1 = 3 * a * b**2
f2 = 3 * a**2 * b
f3 = a**3

# we want the matrix to be moenic in Zn
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
root = roots[0][0]
root = int(root)

secret_message_bytes = root.to_bytes((root.bit_length() + 7) // 8)
secret_message = secret_message_bytes.decode()

json_send({"command" : "solve", "message" : secret_message})
response = json_recv()
print(response["flag"])





