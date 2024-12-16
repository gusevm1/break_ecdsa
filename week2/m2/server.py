import hashlib
from math import ceil
from schnorr import Schnorr, Schnorr_Params
from boilerplate import CommandServer, on_command

MAX_QUERIES = 100

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

# Parameters of the P-521 NIST curve
a = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
b = 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
P_x = 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
P_y = 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
q = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
nistp521_params = Schnorr_Params(a, b, p, P_x, P_y, q)

# Parameters of the brainpoolP512r1 curve
a = 0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca
b = 0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723
p = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3
P_x = 0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822
P_y = 0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892
q = 0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069
brainpoolP512r1_params = Schnorr_Params(a, b, p, P_x, P_y, q)


class FlexibleSignServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.algos = {
            "P-256": Schnorr(nistp256_params),
            "brainpoolP256r1": Schnorr(brainpoolP256r1_params),
            "P-521": Schnorr(nistp521_params),
            "brainpoolP512r1": Schnorr(brainpoolP512r1_params),
        }

        self.keys = {
            curve: algo.KeyGen()
            for curve, algo in self.algos.items()
        }
        print(f"Private keys: {self.keys}")

        self.queries = 0
        self.biggest_nonce_length = 0
        super().__init__(*args, **kwargs)

    @on_command("get_pubkey")
    def handle_getpubkey(self, msg):
        try:
            curve = msg["curve"]
            if curve not in self.algos:
                self.send_message({"error": "Invalid curve"})
                return
            _, pubkey = self.keys[curve]
            self.send_message({"x": int(pubkey.x), "y": int(pubkey.y)})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters: {type(e).__name__} {e}"})

    
    
    @on_command("get_signature")
    def handle_signature(self, msg):
        if self.queries == MAX_QUERIES:
            self.send_message(
                {"error": "Maximum number of signature queries reached"})
            self.close_connection()
            return
        try:
            m = msg["msg"]
            if m == "gimme the flag":
                self.send_message({"error": "Nice try, big guy"})
                return

            curve = msg["curve"]
            if curve not in self.algos:
                self.send_message({"error": "Invalid curve"})
                return

            schnorr = self.algos[curve]
            privkey, _ = self.keys[curve]

            q_size = ceil(schnorr.q.bit_length() / 8)
            # print(f"q_size: {q_size}")

            # Join a few SHA-256 outputs until we get enough bytes
            nonce_bytes = b""
            digest_size = hashlib.sha256().digest_size
            # print(f"digest_size: {digest_size}")
            # print(f"q_size : {q_size}")
            for i in range(q_size // digest_size):
                # print(f"i: {i}")
                H = hashlib.sha256()
                H.update(i.to_bytes(4, "big"))
                # print(H.digest())
                H.update(int(privkey).to_bytes(q_size, "big"))
                # print(H.digest())
                H.update(m.encode())
                # print(H.digest())
                nonce_bytes += H.digest()

            nonce = schnorr.Z_q(int.from_bytes(nonce_bytes))
            # print(f"nonce: {nonce}")
            # print(f"binary nonce: {bin(nonce)[2:]}")
            # print(f"binary nonce length: {len(bin(nonce)[2:])}")
                
            # print(f"binary q: {bin(schnorr.q)[2:]}")
            # print(f"binary q length: {len(bin(schnorr.q)[2:])}")
            # print()
            # print(f"highest_nonce_bits: {self.highest_nonce_bits}")
            # print("----------"*5)

            h, s = schnorr.Sign_FixedNonce(
                nonce, privkey, m, hash_func=hashlib.sha512)
            print(f"nonce: {nonce}, h: {h}, s: {s}")

            self.queries += 1
            self.send_message({"h": int(h), "s": int(s)})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters: {type(e).__name__} {e}"})

    @on_command("solve")
    def handle_verification(self, msg):
        try:
            curve = msg["curve"]
            if curve not in self.algos:
                self.send_message({"error": "Invalid curve"})
                return

            schnorr = self.algos[curve]
            _, pubkey = self.keys[curve]

            h = schnorr.Z_q(msg["h"])
            s = schnorr.Z_q(msg["s"])

            if schnorr.Verify(pubkey, "gimme the flag", h, s, hash_func=hashlib.sha512):
                self.send_message(
                    {"res": "Huh? how did you do that?", "flag": self.flag})
            else:
                self.send_message({"res": "Nah."})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message(
                {"error": f"Invalid parameters: {type(e).__name__} {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    FlexibleSignServer.start_server("0.0.0.0", 40220, flag=flag)
