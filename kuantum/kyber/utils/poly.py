from kuantum.kyber.utils.constants import PARAMS_N, PARAMS_Q, NTT_ZETAS, PARAMS_ETA_1, PARAMS_ETA_2
from kuantum.kyber.utils.constants import COMPRESSED_BYTES_512, COMPRESSED_BYTES_1024, POLY_BYTES
from kuantum.kyber.utils.num_type import int16, uint16, int32, long64, byte
from kuantum.kyber.utils.reduce import barrett_reduce, montgomery_reduce
from kuantum.kyber.utils.ntt import base_multiplier
from kuantum.kyber.utils.byte_ops import gen_cbd_pol
from Crypto.Hash import SHAKE256
from typing import List
import numpy as np


def poly_add(a: List[int], b: List[int]):
    """
    Add two polynomials; no modular reduction is performed

    arg0: first polynomial
    arg1: second polynomial
    """
    c = [a[i] + b[i] for i in range(len(a))]
    return c


def poly_sub(a, b):
    """
    Subtract two polynomials; no modular reduction is performed

    arg0: first polynomial
    arg1: second polynomial
    """
    c = [a[i] - b[i] for i in range(len(a))]
    return c


def poly_conditional_sub_q(r):
    """
    Apply the conditional subtraction of Q (KyberParams) to each coefficient of a

    arg0: polynomial
    """
    for i in range(PARAMS_N):
        r[i] = int16(r[i] - PARAMS_Q)
        r[i] = int16(r[i] + int32(int32(r[i] >> 15) & PARAMS_Q))
    return r


def poly_barret_reduce(r):
    """
    Applies Barrett reduction to all coefficients of a polynomial

    arg0: polynomial
    """
    for i in range(PARAMS_N):
        r[i] = barrett_reduce(r[i])
    return r


def poly_montgomery_reduce(r):
    """
    Applies Montgomery reduction to all coefficients of a polynomial

    arg0: polynomial
    """
    for i in range(PARAMS_N):
        r[i] = montgomery_reduce(long64(r[i]*1353))
    return r


def poly_base_mul(a, b):
    """
    Multiplication of two polynomials in NTT domain

    arg0: first polynomial
    arg1: second polynomial
    """

    for i in range(PARAMS_N // 4):
        rx = base_multiplier(
            a[4 * i + 0], a[4 * i + 1],
            b[4 * i + 0], b[4 * i + 1],
            int16(NTT_ZETAS[64 + i])
        )
        ry = base_multiplier(
            a[4 * i + 2], a[4 * i + 3],
            b[4 * i + 2], b[4 * i + 3],
           int16(NTT_ZETAS[64 + i] * -1)
        )
        a[4 * i + 0] = rx[0]
        a[4 * i + 1] = rx[1]
        a[4 * i + 2] = ry[0]
        a[4 * i + 3] = ry[1]
    return a


def poly_to_bytes(a):
    """
    Serialize a polynomial to a byte array.

    arg0: polynomial
    """
    t0 = 0
    t1 = 0
    r = [0 for _ in range(POLY_BYTES)]
    a = poly_conditional_sub_q(a)
    for i in range(PARAMS_N // 2):
        t0 = uint16(a[2 * i])
        t1 = uint16(a[2 * i + 1])
        r[3 * i + 0] = byte(t0 >> 0)
        r[3 * i + 1] = byte(t0 >> 8) | byte(t1 << 4)
        r[3 * i + 2] = byte(t1 >> 4)
    return r


def poly_from_bytes(a):
    """
    Deserialize a polynomial from a byte array.

    arg0: byte array
    """
    r = [0 for _ in range(POLY_BYTES)]
    for i in range(PARAMS_N // 2):
        r[2 * i] = int16((((a[3 * i + 0] & 0xFF) >> 0) | ((a[3 * i + 1] & 0xFF) << 8)) & 0xFFF)
        r[2 * i + 1] = int16((((a[3 * i + 1] & 0xFF) >> 4) | ((a[3 * i + 2] & 0xFF) << 4)) & 0xFFF)
    return r


def poly_from_msg(msg):
    """
    Convert a 32-byte message to a polynomial.

    arg0: 32-byte message
    """
    r = [0 for _ in range(PARAMS_N)]
    mask = 0
    for i in range(PARAMS_N // 8):
        for j in range(8):
            mask = int16 (-1 * int16 (((msg[i] & 0xFF) >> j) & 1))
            r[8 * i + j] = int16 (mask & int16 ((PARAMS_Q + 1) // 2))
    return r


def poly_to_msg(a):
    """
    Convert a polynomial to a 32-byte message.

    arg0: polynomial
    """
    msg = [0 for _ in range(32)]
    a = poly_conditional_sub_q(a)
    for i in range(PARAMS_N // 8):
        for j in range(8):
            t = int32(((((int32 (a[8 * i + j])) << 1) + (PARAMS_Q // 2)) // PARAMS_Q) & 1)
            msg[i] = byte(msg[i] | (t << j))
    return msg


def poly_compress(a, k):
    """
    Compression and subsequent serialization of a polynomial

    arg0: polynomial
    arg1: value of PARAM_K
    """
    rr = 0
    t = [0 for _ in range(8)]
    a = poly_conditional_sub_q(a)
    if k == 2 or k == 3:
        r = [0 for _ in range(COMPRESSED_BYTES_512)]
        for i in range(PARAMS_N // 8):
            for j in range(8):
                temp1 = int32(a[8 * i + j] << 4)
                temp2 = int32((temp1 + (PARAMS_Q // 2)) // PARAMS_Q)
                t[j] = byte(temp2 & 15)
            r[rr + 0] = byte(t[0] | (t[1] << 4))
            r[rr + 1] = byte(t[2] | (t[3] << 4))
            r[rr + 2] = byte(t[4] | (t[5] << 4))
            r[rr + 3] = byte(t[6] | (t[7] << 4))
            rr = rr + 4
    else:
        r = [0 for _ in range(COMPRESSED_BYTES_1024)]
        for i in range(PARAMS_N // 8):
            for j in range(8):
                temp1 = int32((a[(8 * i) + j] << 5))
                temp2 = int32((temp1 + (PARAMS_Q // 2)) // PARAMS_Q)
                t[j] = byte(temp2 & 31)
            r[rr + 0] = byte((t[0] >> 0) | (t[1] << 5))
            r[rr + 1] = byte((t[1] >> 3) | (t[2] << 2) | (t[3] << 7))
            r[rr + 2] = byte((t[3] >> 1) | (t[4] << 4))
            r[rr + 3] = byte((t[4] >> 4) | (t[5] << 1) | (t[6] << 6))
            r[rr + 4] = byte((t[6] >> 2) | (t[7] << 3))
            rr = rr + 5
    return r


def poly_decompress(a, k):
    """
    De-serialization and subsequent decompression of a polynomial;
    approximate inverse of poly_compress

    arg0: byte array
    arg1: value of PARAM_K
    """
    r = [0 for _ in range(POLY_BYTES)]
    t = [0 for _ in range(8)]
    aa = 0
    if k == 2 or k == 3:
        for i in range(PARAMS_N // 2):
            r[2 * i + 0] = int16((((int32(a[aa] & 0xFF) & 15) * PARAMS_Q) + 8) >> 4)
            r[2 * i + 1] = int16((((int32(a[aa] & 0xFF) >> 4) * PARAMS_Q) + 8) >> 4)
            aa += 1
    else:
        for i in range(PARAMS_N // 8):
            t[0] = long64(int32(a[aa + 0] & 0xFF) >> 0) & 0xFF
            t[1] = long64(byte((int32(a[aa + 0] & 0xFF) >> 5)) | byte(int32(a[aa + 1] & 0xFF) << 3)) & 0xFF
            t[2] = long64(int32(a[aa + 1] & 0xFF) >> 2) & 0xFF
            t[3] = long64(byte((int32(a[aa + 1] & 0xFF) >> 7)) | byte(int32(a[aa + 2] & 0xFF) << 1)) & 0xFF
            t[4] = long64(byte((int32(a[aa + 2] & 0xFF) >> 4)) | byte(int32(a[aa + 3] & 0xFF) << 4)) & 0xFF
            t[5] = long64(int32(a[aa + 3] & 0xFF) >> 1) & 0xFF
            t[6] = long64(byte((int32(a[aa + 3] & 0xFF) >> 6)) | byte(int32(a[aa + 4] & 0xFF) << 2)) & 0xFF
            t[7] = (long64(int32(a[aa + 4] & 0xFF) >> 3)) & 0xFF
            aa = aa + 5
            for j in range(0, 8):
                r[8 * i + j] = int16(((long64(t[j] & 31) * (PARAMS_Q)) + 16) >> 5)
    return r


def get_noise_poly(seed, nonce, k):
    if k == 2:
        l = PARAMS_N * PARAMS_ETA_1 // 4
    else:
        l = PARAMS_N * PARAMS_ETA_2 // 4
    buf = gen_prf_byte_array(seed, nonce, l)
    return gen_cbd_pol(buf, k)


def gen_prf_byte_array(key, nonce, l):
    xof = SHAKE256.new()
    new_key = [0 for _ in range(0, len(key) + 1)]
    for i in range(0, len(key)):
        new_key[i] = key[i]
    new_key[len(key)] = nonce
    new_key = [x & 0xff for x in new_key]
    xof.update(bytearray(new_key))
    generated_hash = xof.read(l)
    generated_hash = [byte(x) for x in generated_hash]
    return generated_hash


__all__ = [
    "poly_add",
    "poly_sub",
    "poly_conditional_sub_q",
    "poly_barret_reduce",
    "poly_montgomery_reduce",
    "poly_base_mul",
    "poly_to_bytes",
    "poly_from_bytes",
    "poly_to_msg",
    "poly_from_msg",
    "poly_compress",
    "poly_decompress",
    "get_noise_poly",
    "gen_prf_byte_array"
]
