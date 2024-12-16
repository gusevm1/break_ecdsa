import json
import logging
import sys
import os
import hashlib
import socket
import time
import secrets
from math import gcd
from sage.all import *
from schnorr import Schnorr, Schnorr_Params, Point, bits_to_int, hash_message_to_bits
from sage.modules.free_module_integer import IntegerLattice
from sympy import symbols, simplify, solve
from schnorr import Schnorr, Schnorr_Params, Point, bits_to_int, hash_message_to_bits

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


def init_schnorr():
    algos = {
          "P-256": Schnorr(nistp256_params),
          "brainpoolP256r1": Schnorr(brainpoolP256r1_params),
          "P-521": Schnorr(nistp521_params),
          "brainpoolP512r1": Schnorr(brainpoolP512r1_params),
      }
    return algos

def get_ith_algo(i):
    algos = init_schnorr()
    return list(algos.keys())[i % 4], list(algos.values())[i % 4]

def get_curves():
    algos = init_schnorr()
    return [algo.curve for algo in algos.values()]


def sign_message(schnorr, privkey, msg):
    h, s = schnorr.Sign(privkey, msg)
    return h, s


def get_signature(msg, curve):
    json_send({"command": "get_signature", "msg": msg, "curve": curve})
    response = json_recv()
    print(response)
    return response["h"], response["s"]

def get_pubkey(curves):
    pubkeys = []
    for curve in curves:
        json_send({"command": "get_pubkey", "curve": curve})
        response = json_recv()
        #print(response)
        pubkeys.append(response)
    return pubkeys

def submit(h, s, curve):
    json_send({"command": "solve", "h": h, "s": s, "curve": curve})
    response = json_recv()
    print(response)
    return response


algos = init_schnorr()
curves = get_curves()

# Constants
MAX_TRIES = 100
MAX_GUESSES = 1
MAX_VECS = 100


# Get public keys
pubkeys = get_pubkey(algos.keys())



curve_name = "P-521"
m = 2
schnorr = get_ith_algo(m)[1]
n = MAX_TRIES
q = algos[curve_name].q
# q length for this algorithm is 521 bits
N = schnorr.q.bit_length()
# L is 9 because nonce length is 512 bits
L = 9

print(N, L, n)

# Collect signatures and messages
messages = [f"gimme the flag{str(i)}" for i in range(MAX_TRIES)]
signatures = [get_signature(msg, curve_name) for i, msg in enumerate(messages)]

h_values = [sig[0] for sig in signatures]
s_values = [sig[1] for sig in signatures]

assert len(s_values) == n == len(messages)

# We have the following signing equation:
# s = k − hx mod q
t_values = h_values
z_values = s_values


# first 8 bits are zero, as the hash function is sha256 twice which has length 512, and q is 521 bits
a = 0b000000000

# u = 2^511 - z as a is zero
u_values = [2 ** (N - L - 1) - z for z in z_values]


# build lattice
lattice = []
for i in range(n):
    row = [0] * (n+1)
    row[i] = q * 2**(L + 1)
    lattice.append(row)

t_scaled = [t * 2**(L + 1) for t in t_values]
# Adjust lattice scaling and last row
last_row = t_scaled + [1]
lattice.append(last_row)
lattice = Matrix(QQ, lattice)

assert lattice.nrows() == n+1 and lattice.ncols() == n+1

us_scaled = [u * 2**(L + 1) for u in u_values]



# lattice is scaled us_scaled is scaled
deteterminant = q**(MAX_TRIES/(MAX_TRIES + 1))
fac= ((MAX_TRIES + 1)/(2 * math.pi * math.e))**(1/2) 
lambd_1 =  deteterminant * fac
k = 0.04 # empirical value
M = int(k * lambd_1/2) 
w_values = us_scaled + [0]
w = vector(QQ, w_values)

# initialize the shortest vector problem
lattice_prime = [
    list(b) + [0] for b in lattice  # Extend each bi with a zero
] + [
    w_values + [M]  # Add (w, M) as the last row
]

# Step 1: Construct the augmented basis matrix B'
lattice_prime = matrix(QQ, lattice_prime)
lattice_prime = lattice_prime.LLL()

f_Ms = list(lattice_prime)

for f_M in f_Ms:
    f = f_M[:-1]
    potential_x = (us_scaled[-1] - f[-1]) % q

    # check if x * P = pubkey
    json_send({"command": "get_pubkey", "curve": "P-521"})
    pubkey = json_recv()
    pubkey_x = pubkey["x"]
    pubkey_y = pubkey["y"]

    schnorr_curve = Schnorr(nistp521_params).curve
    pubkey = Point(schnorr_curve, pubkey_x, pubkey_y )

    P = Point(schnorr_curve, P_x, P_y)
    x_times_P = P * schnorr.Z_q(potential_x)

    if int(x_times_P.x) == pubkey_x and int(x_times_P.y) == pubkey_y:
        print(f"Found the private key: {potential_x}")
        break
    


    
