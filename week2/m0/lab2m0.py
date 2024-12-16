import json
import logging
import sys
import os
import socket

from schnorr import Schnorr, Schnorr_Params, Point

from sage.all import matrix, vector
from sage.all import *

# Change the port to match the challenge you're solving
PORT = 40200

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
num_leaked_bits = 128
max_querries = 5

# Parameters of the P-256 NIST curve
a   = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p   = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q   = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

nistp256_params = Schnorr_Params(a, b, p, P_x, P_y, q)
schnorr = Schnorr(nistp256_params)

import math

h_ = []
s_ = []
nonce_ = []
# setup hnp
for i in range(max_querries):
    json_send({"command":"get_signature", "msg": f"message{i}"})
    response = json_recv()
    h = response["h"]
    s = response["s"]
    nonce = response["nonce"]

    h_.append(h)
    s_.append(s)
    nonce_.append(nonce)

t_ = []
u_ = []
for i in range(max_querries):
    t = h_[i]
    u = (nonce_[i] + 2**127 - s_[i]) % q
    t_.append(t)
    u_.append(u)

N = 256
L = 128


def convert_hidden_number_problem_to_closest_vector_problem(N, L, num_querries, ts, us, q):
    B = matrix(QQ, num_querries + 1, num_querries + 1)
    for i in range(num_querries + 1):
        B[i, i] = q * (2**(L + 1))
        ts = ts + [0]
        B[num_querries, i] = ts[i] * (2**(L + 1)) 
        B[num_querries, num_querries] = 1
    us_ = [u * (2**(L + 1)) for u in us] + [0]
    
    return (B, us_) # return CVP basis matrix B and CVP target vector u

def convert_closest_vector_problem_to_shortest_vector_problem(N, L, num_querries, B, us_):
    determinant = B[0, 0]**(num_querries/(num_querries + 1)) # det(L)^(1/n)
    fac_yes= ((num_querries + 1)/(2 * math.pi * math.e))**(1/2) # sqrt(n / 2 * pi * e)
    lambd_1 =  determinant * fac_yes # lambd_1
    k = 0.0104 # empirical value
    M = int(k * lambd_1/2) 
    
    # Resize by creating a new matrix
    new_size = B.nrows() + 1  # Add one extra row and column
    B_ = matrix(QQ, new_size, new_size)  # Initialize with zeros

    # Copy original elements into the resized matrix
    for i in range(B.nrows()):
        for j in range(B.ncols()):
            B_[i, j] = B[i, j]
    
    
    for i in range(B.ncols() + 1):
        if i != B.ncols():
            B_[num_querries + 1, i] = us_[i]
        else:
            B_[num_querries + 1, i] = M
    return B_

def validate_x(x, P_x, P_y, schnorr): # check if given x generates Q
    json_send({"command": "get_pubkey"})
    response = json_recv()
    Q_x, Q_y = response["x"], response["y"]
    P = Point(schnorr.curve, P_x, P_y)
    xP = P * schnorr.Z_q(x)
    try: 
        return int(xP.x) == Q_x and int(xP.y) == Q_y
    
    except AttributeError: # if it's the point at infinity an error is thrown
        return False

def find_a_valid_x(N, L, num_querries, ts, us, q, P_x, P_y, schnorr):
    B, us = convert_hidden_number_problem_to_closest_vector_problem(N, L, num_querries, ts, us, q)
    B_ = convert_closest_vector_problem_to_shortest_vector_problem(N, L, num_querries, B, us) # B' Kannan embedding

    f = list(B_.LLL()) # (f, M) and general shortest vectors in reduced lattice, -> list of possible candidates

    for i in range(len(f)):
        shortest = f[i] # in fact, high prop for the second longest
        x = (us[-1] - shortest[-2]) % q # v = u_cvp - f, the second last since f' = [f, M]
        if validate_x(x, P_x, P_y, schnorr) == True:
            return x
    
    return None




x = find_a_valid_x(N, L, max_querries, t_, u_, q, P_x, P_y, schnorr)
#print(x)

h, s = schnorr.Sign_Deterministic(x, "gimme the flag")
json_send({"command": "solve", "h": int(h), "s": int(s)})
response = json_recv()
print(response["flag"])



    

