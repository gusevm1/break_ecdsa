import secrets
import warnings
import hashlib
import hmac

from typing import Callable, Optional, Tuple
from sage.all import Zmod, Integer, ceil

# Used for typing purposes
from sage.rings.finite_rings.integer_mod import IntegerMod_int

"""Schnorr Implementation

This module implements Schnorr KeyGen, Verification and Signing.

Authors:
    Jan Gilcher, Kien Tuong Truong
"""

HashFunc = Callable[[], "hashlib._Hash"]


def hash_message_to_bits(msg: bytes, hash_func: HashFunc):
    """Hash a string to a string of bits

    Args:
        msg (str): The message to be hashed

    Returns:
        str: a binary string in big-endian format that represents the hash of msg
    """

    h = hash_func()
    h.update(msg)
    h_as_bits = ''.join(format(byte, '08b') for byte in h.digest())
    return h_as_bits


def bits_to_int(h_as_bits: str, q: int) -> IntegerMod_int:
    """Convert a truncated binary string in big-endian format to an integer modulo q

    Args:
        h_as_bits: a binary string in big-endian format
        q: the modulus of the result

    Returns:
        IntegerMod_int: the integer representation of h_as_bits in the ring of integers mod q
    """

    return Zmod(q)(Integer(h_as_bits, base=2))


class Curve:
    """An elliptic curve over the integers modulo p

    We use the short Weierstrass form of representation.

    Attributes:
        p (int): the modulus of the ring
        Z_p (IntegerModRing): the ring modulo p over which the curve is defined
        a (IntegerMod_int): the `a` parameter of the curve
        b (IntegerMod_int): the `b` parameter of the curve
    """

    def __init__(self, a, b, p):
        self.p = p
        self.Z_p = Zmod(p)
        self.a = self.Z_p(a)
        self.b = self.Z_p(b)

    def is_singular(self) -> bool:
        """Check whether the curve is singular

        Returns:
            bool: True if the curve is singular (i.e. its discriminant is 0) and False otherwise
        """
        return 4 * self.a**3 + 27 * self.b**2 == 0

    def on_curve(self, x, y) -> bool:
        """Check whether a point of given (x,y) coordinates lays on the curve

        Returns:
            bool: True if the curve if the point is on the curve (i.e. its coordinates fulfill the
                curve equation over the base field) and False otherwise
        """
        x = self.Z_p(x)
        y = self.Z_p(y)
        return y**2 - x**3 - self.a * x - self.b == 0

    @property
    def infinity_point(self):
        """Get the point at infinity for the curve

        Returns:
            Point: the point at infinity for the curve
        """
        return PointInf(self)

    def __str__(self):
        return f'<Elliptic Curve over Z mod {p} with equation y^2 = x^3 + {a}x + {b}>'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Curve):
            return False
        return self.a == other.a and self.b == other.b and self.p == other.p

    def __contains__(self, item: "Point") -> bool:
        if not isinstance(item, Point):
            return False

        return self == item.curve and self.on_curve(item.x, item.y)


class Point:
    """A point over an elliptic curve

    Attributes:
        curve (Curve): the curve to which the point belongs
        x (IntegerMod_int): the x-coordinate of the point, belongs in Z mod p
        y (IntegerMod_int): the y-coordinate of the point, belongs in Z mod p
    """

    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = curve.Z_p(x)
        self.y = curve.Z_p(y)

        if not self.curve.on_curve(self.x, self.y):
            warnings.warn(
                f'Point ({self.x}, {self.y}) is not on curve "{self.curve}"')

    def __str__(self):
        return f'({self.x}, {self.y})'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return False

        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __neg__(self) -> "Point":
        return Point(self.curve, self.x, -self.y)

    def _double(self) -> "Point":
        _lambda = (3 * self.x**2 + self.curve.a) / (2 * self.y)
        x_r = _lambda**2 - 2*self.x
        y_r = -(self.y + _lambda * (x_r - self.x))
        return Point(self.curve, x_r, y_r)

    def __add__(self, other: "Point"):
        if isinstance(other, PointInf):
            return self

        if isinstance(other, Point):
            if self.x == other.x and self.y == other.y:
                return self._double()

            if self.x == other.x and self.y != other.y:
                return self.curve.infinity_point

            _lambda = (self.y - other.y) / (self.x - other.x)
            x_r = _lambda**2 - self.x - other.x
            y_r = -(self.y + _lambda * (x_r - self.x))
            return Point(self.curve, x_r, y_r)

        raise TypeError(
            f'Unsupported operand type(s) for point addition: {type(other)}')

    def __rmul__(self, other) -> "Point":
        try:
            scalar = Integer(other)
        except:
            raise TypeError(
                f'Unsupported operand type(s) for scalar multiplication: {type(other)}')

        result = [PointInf(self.curve), self]

        # iterate over all bits of "scalar" starting by the MSB
        for bit in reversed(scalar.bits()):
            # time.sleep(1e-4) # amplify the side channel
            result[1 - bit] = result[1 - bit] + result[bit]
            result[bit] = result[bit] + result[bit]
        return result[0]

    def __mul__(self, other) -> "Point":
        return self.__rmul__(other)


class PointInf(Point):
    """A special point on an elliptic curve that acts as the neutral element for addition

    Attributes:
        curve (Curve): the elliptic curve to which the point belongs
    """

    def __init__(self, curve):
        self.curve = curve

    def __eq__(self, other: object):
        if not isinstance(other, PointInf):
            return False
        return self.curve == other.curve

    def __neg__(self):
        return self

    def __add__(self, other: Point):
        if isinstance(other, PointInf):
            return self
        if isinstance(other, Point):
            return other
        raise TypeError(
            f'Unsupported operand type(s) for point addition: expected Point, got {type(other)}')

    def scalar_multiply(self, scalar):
        return self


class Schnorr_Params:
    """A container class for parameters that define an Schnorr operation

    Attributes:
        curve (Curve): the elliptic curve on which the Schnorr operations are done
        P (Point): the base point of the group
        q (Integer): the order of the base point
    """

    def __init__(self, a, b, p, P_x, P_y, q):
        self.curve = Curve(a, b, p)
        self.P = Point(self.curve, P_x, P_y)
        self.q = q


class Schnorr():
    """A class that collects Schnorr operations

    The values in `params` are expanded and saved as attributes for your convenience.

    Attributes:
        curve (Curve): the elliptic curve on which the Schnorr operations are done
        p (Integer): the modulus of field of the elliptic curve `curve`
        P (Point): the base point of the group
        q (Integer): the order of the base point
        Z_q (IntegerModRing): the ring of integers mod q
    """

    def __init__(self, params):
        self.curve = params.curve
        self.p = params.curve.p
        self.P = params.P
        self.q = params.q
        self.Z_q = Zmod(self.q)

    @property
    def qlen(self):
        return self.q.bit_length()

    @property
    def rlen(self):
        # We keep this in bytes so we can use it in int.to_bytes without having to divide by 8
        return ceil(self.qlen / 8)

    def _int2octets(self, x: IntegerMod_int) -> bytes:
        """Converts an integer modulo q to a byte string of length 8*rlen"""

        return int(x).to_bytes(self.rlen, byteorder="big")

    def _bits2int(self, b: bytes, blen: Optional[int] = None) -> int:
        """Converts a bit string of blen bits and outputs a non-negative integer that is less than 2^qlen"""

        if blen is None:
            # This covers the case in which `b` should have fewer bits than a multiple of 8.
            # We can't know that just by looking at the string.
            blen = len(b) * 8

        b_bits = bin(int.from_bytes(b, byteorder="big"))[2:].zfill(blen)

        if self.qlen < blen:
            # Take the leftmost qlen bits
            b_bits = b_bits[:self.qlen]
        else:
            # Pad with zeros on the left
            b_bits = b_bits.zfill(self.qlen)

        return int(b_bits, base=2)

    def _bits2octets(self, b: bytes) -> bytes:
        """Converts a bit string of blen bits to a byte string of 8*rlen"""

        z1 = self._bits2int(b)
        z2 = self.Z_q(z1)
        return self._int2octets(z2)

    def generate_deterministic_nonce(
        self,
        msg: str,
        privkey: IntegerMod_int,
        hash_func: HashFunc = hashlib.sha256
    ) -> IntegerMod_int:
        """Deterministically generates a nonce using DRBG based on RFC 6979

        Args:
            msg (str): the message to sign
            privkey (IntegerMod_int): the private key to be used for signing
            hash_func (Callable[[], hashlib._Hash]): the hash function to be used for the DRBG

        Returns:
            IntegerMod_int: the nonce k to be used during signing
        """

        # Steps from Section 3.2 of RFC 6979

        # Step a
        H = hash_func()
        H.update(msg.encode())
        h1 = H.digest()

        # Step b
        V = bytes([0x01] * H.digest_size)

        # Step c
        K = bytes([0x00] * H.digest_size)

        # Step d
        x_bytes = self._int2octets(privkey)
        h1_bytes = self._bits2octets(h1)
        H_k = hmac.new(K, digestmod=hash_func)
        H_k.update(V)
        H_k.update(bytes([0x00]))
        H_k.update(x_bytes)
        H_k.update(h1_bytes)
        K = H_k.digest()

        # Step e
        H_k = hmac.new(K, digestmod=hash_func)
        H_k.update(V)
        V = H_k.digest()

        # Step f
        H_k = hmac.new(K, digestmod=hash_func)
        H_k.update(V)
        H_k.update(bytes([0x01]))
        H_k.update(x_bytes)
        H_k.update(h1_bytes)
        K = H_k.digest()

        # Step g
        H_k = hmac.new(K, digestmod=hash_func)
        H_k.update(V)
        V = H_k.digest()

        # Step h
        while True:
            # Step h1
            T = b""
            tlen = 0

            # Step h2
            while tlen < self.qlen:
                H_k = hmac.new(K, digestmod=hash_func)
                H_k.update(V)
                V = H_k.digest()
                T += V
                tlen += 8 * H.digest_size

            # Step h3
            k = self._bits2int(T)
            if k >= 1 and k < self.q:
                return self.Z_q(k)

            # Step h4
            H_k = hmac.new(K, digestmod=hash_func)
            H_k.update(V)
            H_k.update(bytes([0x00]))
            K = H_k.digest()

            H_k = hmac.new(K, digestmod=hash_func)
            H_k.update(V)
            V = H_k.digest()

    def KeyGen(self) -> Tuple[IntegerMod_int, Point]:
        """Generates an Schnorr key pair

        Returns:
            IntegerMod_int: the private key
            Point: the public key
        """

        x = 0
        while x == 0:
            x = secrets.randbelow(self.q)
        x = self.Z_q(x)
        Q = x * self.P
        return x, Q

    def Sign_FixedNonce(self, nonce: IntegerMod_int, privkey: IntegerMod_int, msg: str, hash_func: HashFunc = hashlib.sha256) -> Tuple[IntegerMod_int, IntegerMod_int]:
        """Computes a Schnorr signature for a previously chosen nonce

        Args:
            nonce (IntegerMod_int): the nonce to be used for signing
            privkey (IntegerMod_int): the private key to be used for signing
            msg (str): the message to sign

        Returns:
            Tuple[IntegerMod_int, IntegerMod_int]: the tuple (r, s) of the signature
        """

        r = self.Z_q((nonce * self.P).x)
        r_size = ceil(int(self.q).bit_length() / 8)
        h = bits_to_int(hash_message_to_bits(
            msg.encode() + int(r).to_bytes(r_size, 'big'), hash_func), self.q)
        s = nonce - h * privkey
        return h, s

    def Sign(self, privkey: IntegerMod_int, msg: str, hash_func: HashFunc = hashlib.sha256) -> Tuple[IntegerMod_int, IntegerMod_int]:
        """Computes a Schnorr signature for a randomly chosen nonce

        This method samples a nonce randomly and uses it to sign.

        Args:
            privkey (IntegerMod_int): the private key to be used for signing
            msg (str): the message to sign

        Returns:
            Tuple[IntegerMod_int, IntegerMod_int]: the tuple (h, s) of the signature
        """

        h, s = 0, 0
        while h == 0 or s == 0:
            k = self.Z_q(1 + secrets.randbelow(self.q - 1))
            h, s = self.Sign_FixedNonce(k, privkey, msg, hash_func)
        return h, s

    def Sign_Deterministic(self, privkey: IntegerMod_int, msg: str, hash_func: HashFunc = hashlib.sha256) -> Tuple[IntegerMod_int, IntegerMod_int]:
        """Computes a Schnorr signature with a deterministically-generated nonce

        This method generates a nonce using the procedure of RFC 6979 and uses it to sign.

        Args:
            privkey (IntegerMod_int): the private key to be used for signing
            msg (str): the message to sign

        Returns:
            Tuple[IntegerMod_int, IntegerMod_int]: the tuple (h, s) of the signature
        """

        k = self.generate_deterministic_nonce(msg, privkey)
        h, s = self.Sign_FixedNonce(k, privkey, msg, hash_func)
        return h, s

    def Verify(self, pubkey: Point, msg: str, h: IntegerMod_int, s: IntegerMod_int, hash_func: HashFunc = hashlib.sha256) -> bool:
        """Verifies an Schnorr signature

        Args:
            pubkey (Point): the public key to be used for verification
            msg (str): the message over which the signature was computed
            h (IntegerMod_int): the first half of the signature
            s (IntegerMod_int): the second half of the signature

        Returns:
            bool: True if the signature verifies, False otherwise
        """

        if h < 1 or Integer(h) > self.q or s < 1 or Integer(s) > self.q:
            return False

        r = self.Z_q((s*self.P + h*pubkey).x)
        r_size = ceil(int(self.q).bit_length() / 8)
        h2 = bits_to_int(
            hash_message_to_bits(
                msg.encode() + int(r).to_bytes(r_size, 'big'),
                hash_func
            ), self.q
        )

        return h2 == h


if __name__ == "__main__":
    # A small test suite for verifying that everything works
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    P_x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
    P_y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

    nistp256_params = Schnorr_Params(a, b, p, P_x, P_y, q)

    Zp = Zmod(p)
    Zq = Zmod(q)

    h = Zq(46256504752728182517572557292731102648253482250024989877906844939221147908807)
    s = Zq(35020613240547933090526181399501852248073339088611794205700950327641427067839)

    k = Zq(3637810214562823320177776556129209540520105078938814552344602482387198586694)
    x = Zq(26606094427569514386736378322189262085314561879458443906133857785152124386158)
    X = x * nistp256_params.P

    msg = "I can't not overthink it, it's impossible"

    schnorr = Schnorr(nistp256_params)
    h1, s1 = schnorr.Sign_FixedNonce(k, x, msg)

    assert h == h1
    assert s == s1
    assert schnorr.Verify(X, msg, h1, s1)
