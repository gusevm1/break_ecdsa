import json
import logging
import sys
import os
import socket

from schnorr import Schnorr, Schnorr_Params, Point

from sage.all import matrix, vector
from sage.all import *

# Change the port to match the challenge you're solving
PORT = 40220

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


# Parameters of the P-256 NIST curve
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
nistp256_params = Schnorr_Params(a, b, p, P_x, P_y, q)

# Parameters of the brainpoolP256r1 curve
a = 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9
b = 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6
p = 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377
P_x = 0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262
P_y = 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997
q = 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7
brainpoolP256r1_params = Schnorr_Params(a, b, p, P_x, P_y, q)

# Parameters of the brainpoolP512r1 curve
a = 0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca
b = 0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723
p = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3
P_x = 0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822
P_y = 0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892
q = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069
brainpoolP512r1_params = Schnorr_Params(a, b, p, P_x, P_y, q)

# Parameters of the P-521 NIST curve
a = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
b = 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
P_x = 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
P_y = 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
q = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
nistp521_params = Schnorr_Params(a, b, p, P_x, P_y, q)



nistp256_params = Schnorr_Params(a, b, p, P_x, P_y, q)
schnorr = Schnorr(nistp521_params)

import math


# for P-521 we notice that the binary nonce has at most 512 bits!
# THE LEADING 9 BITS ARE 0
num_leaked_bits = 9
max_querries = 100

N = 521
L = 9


h_ = []
s_ = []
# setup hnp
for i in range(max_querries):
    json_send({"command":"get_signature", "msg": f"message{i}", "curve": "P-521"})
    response = json_recv()
    
    h = response["h"]
    s = response["s"]
    h_.append(h)
    s_.append(s)

t_ = []
u_ = []

for i in range(max_querries):
    t = h_[i]
    u = (0 * 2**(N-L) + 2**(N-L-1) - s_[i]) % q # 9 msb are 0
    t_.append(t)
    u_.append(u)

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
    deteterminant = B[0, 0]**(num_querries/(num_querries + 1)) # det(L)^(1/n)
    factor= ((num_querries + 1)/(2 * math.pi * math.e))**(1/2) # sqrt(n / 2 * pi * e)
    lambd_1 =  deteterminant * factor # lambd_1
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
    json_send({"command": "get_pubkey", "curve": "P-521"})
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
        if validate_x(x, P_x, P_y, schnorr):
            return x
    
    return None

x = find_a_valid_x(N, L, max_querries, t_, u_, q, P_x, P_y, schnorr)
#print(x)


# use the signing procedure that is used on the server
import hashlib
nonce_bytes = b""
digest_size, q_size = 32, 66 # parameters for P-521
for i in range(q_size // digest_size):
    H = hashlib.sha256()
    H.update(i.to_bytes(4, "big"))
    H.update(int(x).to_bytes(q_size, "big"))
    H.update("gimme the flag".encode())
    nonce_bytes += H.digest()

nonce = schnorr.Z_q(int.from_bytes(nonce_bytes))
h, s = schnorr.Sign_FixedNonce(
                nonce, x, "gimme the flag", hash_func=hashlib.sha512)


json_send({"command": "solve", "curve":"P-521", "h": int(h), "s": int(s)})
response = json_recv()
flag = response["flag"]
print(flag)
