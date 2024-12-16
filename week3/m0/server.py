from math import gcd
import secrets
from boilerplate import CommandServer, on_command, on_startup

from Crypto.Util.number import getPrime
from sage.all import Zmod

N_BIT_LENGTH = 1024

def get_random_string() -> str:
    return secrets.token_hex(8)

class RSAEncServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag

        while True:
            self.p = getPrime(N_BIT_LENGTH // 2)
            self.q = getPrime(N_BIT_LENGTH // 2)
            self.e = 3
            if gcd(self.e, (self.p - 1) * (self.q - 1)) == 1:
                break

        self.n = self.p * self.q

        self.Zn = Zmod(self.n)
        super().__init__(*args, **kwargs)

    @on_startup()
    def handle_startup(self):
        self.secret_message = get_random_string()

    @on_command("get_pubkey")
    def handle_getpubkey(self, msg):
        self.send_message({"n": int(self.n), "e": int(self.e)})

    @on_command("get_ciphertext")
    def handle_ciphertext(self, msg):
        # I've been told that I have to use PKCS7 for cryptography...

        # Padding
        print(f"Secret message: {self.secret_message}")
        print(f"Secret messsage encoded: {self.secret_message.encode()}")
        print(f"secret message int: {int.from_bytes(self.secret_message.encode())}")
        padded_ptxt = b'\x00' + self.secret_message.encode()
        temp = padded_ptxt
        print(f"len padded_ptxt: {len(padded_ptxt)}")
        # print(f"Padded plaintext: {padded_ptxt}")
        to_add = N_BIT_LENGTH // 8 - len(padded_ptxt)
        # print(f"Padding with {to_add} bytes")
        print(f"padding: {int.from_bytes(bytes([to_add] * to_add))}")
        padded_ptxt += bytes([to_add] * to_add)
        # print(f"Padded plaintext: {padded_ptxt}")
        ptxt_int = int.from_bytes(padded_ptxt)
        # print(f"Plaintext int: {ptxt_int}")

        print(f"binary padded_ptxt: {bin(int.from_bytes(padded_ptxt))[2:]}")
        print(f"bytes padded_ptxt: {padded_ptxt}, len: {len(padded_ptxt)}")
        
        print(f"binary plaintext:   {bin(int.from_bytes(temp))[2:]}, len: {len(bin(int.from_bytes(temp))[2:])}")
        print(f"bytes plaintext: {temp}, len: {len(temp)}")

        # Encrypt
        ctxt_int = self.Zn(ptxt_int) ** self.e
        print(f"Ciphertext int: {int(ctxt_int)}")

        # Encode and send
        ctxt_bytes = int(ctxt_int).to_bytes(N_BIT_LENGTH // 8)
        print(f"Ciphertext bytes: {ctxt_bytes}")
        self.send_message({"ciphertext": ctxt_bytes.hex()})


    @on_command("solve")
    def handle_verification(self, msg):
        try:
            guess = msg["message"]
            if guess == self.secret_message:
                self.send_message({"res": "Oh no, my secrets!", "flag": self.flag})
            else:
                self.send_message({"res": "Nah."})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    RSAEncServer.start_server("0.0.0.0", 40300, flag=flag)
