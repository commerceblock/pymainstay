# Copyright (c) 2019 CommerceBlock Team
# Use of this source code is governed by an MIT
# license that can be found in the LICENSE file.

# Copyright (C) 2018 The Electrum developers

import base64
import hmac
import hashlib
import sys
from typing import Union
import time
import random
import os
import binascii

import ecdsa
from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.util import string_to_number, number_to_string

CURVE_ORDER = SECP256k1.order

bfh = bytes.fromhex
hfu = binascii.hexlify

def bh2u(x):
    return hfu(x).decode('ascii')

def to_bytes(something, encoding='utf8'):
    if isinstance(something, bytes):
        return something
    if isinstance(something, str):
        return something.encode(encoding)
    elif isinstance(something, bytearray):
        return bytes(something)
    else:
        raise TypeError("Not a string or bytes like object")

def sha256(x: bytes) -> bytes:
    x = to_bytes(x, 'utf8')
    return bytes(hashlib.sha256(x).digest())

def Hash(x: bytes) -> bytes:
    x = to_bytes(x, 'utf8')
    out = bytes(sha256(sha256(x)))
    return out

def hash_160(x: bytes) -> bytes:
    md = hashlib.new('ripemd160')
    md.update(sha256(x))
    return md.digest()

def key_gen(extra):
    entropy = str(os.urandom(32)) \
        + str(random.randrange(2**256)) \
        + str(int(time.time() * 1000000)) \
        + str(extra)
    return bh2u(sha256(to_bytes(entropy)))

def generator():
    return ECPubkey.from_point(generator_secp256k1)

def point_at_infinity():
    return ECPubkey(None)

def sig_string_from_der_sig(der_sig, order=CURVE_ORDER):
    r, s = ecdsa.util.sigdecode_der(der_sig, order)
    return ecdsa.util.sigencode_string(r, s, order)

def der_sig_from_sig_string(sig_string, order=CURVE_ORDER):
    r, s = ecdsa.util.sigdecode_string(sig_string, order)
    return ecdsa.util.sigencode_der_canonize(r, s, order)

def der_sig_from_r_and_s(r, s, order=CURVE_ORDER):
    return ecdsa.util.sigencode_der_canonize(r, s, order)

def get_r_and_s_from_der_sig(der_sig, order=CURVE_ORDER):
    r, s = ecdsa.util.sigdecode_der(der_sig, order)
    return r, s

def get_r_and_s_from_sig_string(sig_string, order=CURVE_ORDER):
    r, s = ecdsa.util.sigdecode_string(sig_string, order)
    return r, s

def sig_string_from_r_and_s(r, s, order=CURVE_ORDER):
    return ecdsa.util.sigencode_string_canonize(r, s, order)

def point_to_ser(P, compressed=True) -> bytes:
    if isinstance(P, tuple):
        assert len(P) == 2, 'unexpected point: %s' % P
        x, y = P
    else:
        x, y = P.x(), P.y()
    if x is None or y is None:  # infinity
        return None
    if compressed:
        return bfh(('%02x' % (2+(y&1))) + ('%064x' % x))
    return bfh('04'+('%064x' % x)+('%064x' % y))

def is_odd(x, y):
    curve = curve_secp256k1
    if curve.contains_point(x, y):
        return bool(y & 1)
    else:
        raise Exception('is_odd: Point not found on elliptic curve.')

def get_y_coord_from_x(x, odd=True):
    curve = curve_secp256k1
    _p = curve.p()
    _a = curve.a()
    _b = curve.b()
    for offset in range(128):
        Mx = x + offset
        My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
        My = pow(My2, (_p + 1) // 4, _p)
        if curve.contains_point(Mx, My):
            if odd == bool(My & 1):
                return My
            return _p - My
    raise Exception('ECC_YfromX: No Y found')

def ser_to_point(ser: bytes) -> (int, int):
    if ser[0] not in (0x02, 0x03, 0x04):
        raise ValueError('Unexpected first byte: {}'.format(ser[0]))
    if ser[0] == 0x04:
        return string_to_number(ser[1:33]), string_to_number(ser[33:])
    x = string_to_number(ser[1:])
    return x, get_y_coord_from_x(x, ser[0] == 0x03)


def _ser_to_python_ecdsa_point(ser: bytes) -> ecdsa.ellipticcurve.Point:
    x, y = ser_to_point(ser)
    try:
        return Point(curve_secp256k1, x, y, CURVE_ORDER)
    except:
        raise InvalidECPointException()

class InvalidECPointException(Exception):
    """e.g. not on curve, or infinity"""

class _MyVerifyingKey(ecdsa.VerifyingKey):
    @classmethod
    def from_signature(klass, sig, recid, h, curve):  # TODO use libsecp??
        """ See http://www.secg.org/download/aid-780/sec1-v2.pdf, chapter 4.1.6 """
        from ecdsa import util, numbertheory
        from . import msqr
        curveFp = curve.curve
        G = curve.generator
        order = G.order()
        # extract r,s from signature
        r, s = util.sigdecode_string(sig, order)
        # 1.1
        x = r + (recid//2) * order
        # 1.3
        alpha = ( x * x * x  + curveFp.a() * x + curveFp.b() ) % curveFp.p()
        beta = msqr.modular_sqrt(alpha, curveFp.p())
        y = beta if (beta - recid) % 2 == 0 else curveFp.p() - beta
        # 1.4 the constructor checks that nR is at infinity
        try:
            R = Point(curveFp, x, y, order)
        except:
            raise InvalidECPointException()
        # 1.5 compute e from message:
        e = string_to_number(h)
        minus_e = -e % order
        # 1.6 compute Q = r^-1 (sR - eG)
        inv_r = numbertheory.inverse_mod(r,order)
        try:
            Q = inv_r * ( s * R + minus_e * G )
        except:
            raise InvalidECPointException()
        return klass.from_public_point( Q, curve )


class _MySigningKey(ecdsa.SigningKey):
    """Enforce low S values in signatures"""

    def sign_number(self, number, entropy=None, k=None):
        r, s = ecdsa.SigningKey.sign_number(self, number, entropy, k)
        if s > CURVE_ORDER//2:
            s = CURVE_ORDER - s
        return r, s


class _PubkeyForPointAtInfinity:
    point = ecdsa.ellipticcurve.INFINITY


class ECPubkey(object):

    def __init__(self, b: bytes):
        if b is not None:
            point = _ser_to_python_ecdsa_point(b)
            self._pubkey = ecdsa.ecdsa.Public_key(generator_secp256k1, point)
        else:
            self._pubkey = _PubkeyForPointAtInfinity()

    @classmethod
    def from_sig_string(cls, sig_string: bytes, recid: int, msg_hash: bytes):
        if len(sig_string) != 64:
            raise Exception('Wrong encoding')
        if recid < 0 or recid > 3:
            raise ValueError('recid is {}, but should be 0 <= recid <= 3'.format(recid))
        ecdsa_verifying_key = _MyVerifyingKey.from_signature(sig_string, recid, msg_hash, curve=SECP256k1)
        ecdsa_point = ecdsa_verifying_key.pubkey.point
        return ECPubkey.from_point(ecdsa_point)

    @classmethod
    def from_signature65(cls, sig: bytes, msg_hash: bytes):
        if len(sig) != 65:
            raise Exception("Wrong encoding")
        nV = sig[0]
        if nV < 27 or nV >= 35:
            raise Exception("Bad encoding")
        if nV >= 31:
            compressed = True
            nV -= 4
        else:
            compressed = False
        recid = nV - 27
        return cls.from_sig_string(sig[1:], recid, msg_hash), compressed

    @classmethod
    def from_point(cls, point):
        _bytes = point_to_ser(point, compressed=False)  # faster than compressed
        return ECPubkey(_bytes)

    def get_public_key_bytes(self, compressed=True):
        if self.is_at_infinity(): raise Exception('point is at infinity')
        return point_to_ser(self.point(), compressed)

    def get_public_key_hex(self, compressed=True):
        return bh2u(self.get_public_key_bytes(compressed))

    def point(self) -> (int, int):
        return self._pubkey.point.x(), self._pubkey.point.y()

    def __mul__(self, other: int):
        if not isinstance(other, int):
            raise TypeError('multiplication not defined for ECPubkey and {}'.format(type(other)))
        ecdsa_point = self._pubkey.point * other
        return self.from_point(ecdsa_point)

    def __rmul__(self, other: int):
        return self * other

    def __add__(self, other):
        if not isinstance(other, ECPubkey):
            raise TypeError('addition not defined for ECPubkey and {}'.format(type(other)))
        ecdsa_point = self._pubkey.point + other._pubkey.point
        return self.from_point(ecdsa_point)

    def __eq__(self, other):
        return self._pubkey.point.x() == other._pubkey.point.x() \
                and self._pubkey.point.y() == other._pubkey.point.y()

    def __ne__(self, other):
        return not (self == other)

    def verify_message_for_address(self, sig65: bytes, message: bytes) -> None:
        h = Hash(message)
        public_key, compressed = self.from_signature65(sig65, h)
        # check public key
        print(public_key)
        if public_key != self:
            raise Exception("Bad signature")
        # check message
        self.verify_message_hash(sig65[1:], h)

    def verify_message_hash(self, sig_string: bytes, msg_hash: bytes) -> None:
        if len(sig_string) != 64:
            raise Exception('Wrong encoding')
        ecdsa_point = self._pubkey.point
        verifying_key = _MyVerifyingKey.from_public_point(ecdsa_point, curve=SECP256k1)
        verifying_key.verify_digest(sig_string, msg_hash, sigdecode=ecdsa.util.sigdecode_string)

    def ecdh(self, scalar: int):
        """
        Compute the elliptic curve Diffie-Hellman shared secret
        """
        key=self*scalar
        public_key_bytes=key.get_public_key_bytes(compressed=True)
        return bytes(hashlib.sha256(bytes(public_key_bytes)).digest())

    @classmethod
    def order(cls):
        return CURVE_ORDER

    def is_at_infinity(self):
        return self == point_at_infinity()

def is_secret_within_curve_range(secret: Union[int, bytes]) -> bool:
    if isinstance(secret, bytes):
        secret = string_to_number(secret)
    return 0 < secret < CURVE_ORDER


class ECPrivkey(ECPubkey):

    def __init__(self, privkey_bytes: bytes):
        if len(privkey_bytes) != 32:
            raise Exception('unexpected size for secret. should be 32 bytes, not {}'.format(len(privkey_bytes)))
        secret = string_to_number(privkey_bytes)
        if not is_secret_within_curve_range(secret):
            raise InvalidECPointException('Invalid secret scalar (not within curve order)')
        self.secret_scalar = secret

        point = generator_secp256k1 * secret
        super().__init__(point_to_ser(point))
        self._privkey = ecdsa.ecdsa.Private_key(self._pubkey, secret)

    @classmethod
    def from_secret_scalar(cls, secret_scalar: int):
        secret_bytes = number_to_string(secret_scalar, CURVE_ORDER)
        return ECPrivkey(secret_bytes)

    @classmethod
    def from_arbitrary_size_secret(cls, privkey_bytes: bytes):
        """This method is only for legacy reasons. Do not introduce new code that uses it.
        Unlike the default constructor, this method does not require len(privkey_bytes) == 32,
        and the secret does not need to be within the curve order either.
        """
        return ECPrivkey(cls.normalize_secret_bytes(privkey_bytes))

    @classmethod
    def normalize_secret_bytes(cls, privkey_bytes: bytes) -> bytes:
        scalar = string_to_number(privkey_bytes) % CURVE_ORDER
        if scalar == 0:
            raise Exception('invalid EC private key scalar: zero')
        privkey_32bytes = number_to_string(scalar, CURVE_ORDER)
        return privkey_32bytes

    def sign(self, data: bytes, sigencode=None, sigdecode=None) -> bytes:
        if sigencode is None:
            sigencode = sig_string_from_r_and_s
        if sigdecode is None:
            sigdecode = get_r_and_s_from_sig_string
        private_key = _MySigningKey.from_secret_exponent(self.secret_scalar, curve=SECP256k1)
        sig = private_key.sign_digest_deterministic(data, hashfunc=hashlib.sha256, sigencode=sigencode)
        public_key = private_key.get_verifying_key()
        if not public_key.verify_digest(sig, data, sigdecode=sigdecode):
            raise Exception('Sanity check verifying our own signature failed.')
        return sig

    def sign_message(self, message: bytes, is_compressed: bool) -> bytes:

        sig_string = self.sign(message,
                               sigencode=der_sig_from_r_and_s,
                               sigdecode=get_r_and_s_from_der_sig)
        return sig_string

