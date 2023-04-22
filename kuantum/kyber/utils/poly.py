from kuantum.kyber.utils.constants import PARAMS_N, PARAMS_Q, NTT_ZETAS, PARAMS_ETA_1, PARAMS_ETA_2
from kuantum.kyber.utils.constants import COMPRESSED_BYTES_512, COMPRESSED_BYTES_1024, POLY_BYTES
from kuantum.kyber.utils.num_type import int16, uint16, uint32, byte
from kuantum.kyber.utils.reduce import barrett_reduce, montgomery_reduce
from kuantum.kyber.utils.ntt import base_multiplier
from kuantum.kyber.utils.byte_ops import gen_cbd_pol
from Crypto.Hash import SHAKE256
from typing import List


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
        r[i] -= int16(PARAMS_Q)
        r[i] += (r[i] >> 31) & int16(PARAMS_Q)
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
        r[i] = montgomery_reduce(r[i])
    return r


def poly_base_mul(a, b):
    """
    Multiplication of two polynomials in NTT domain

    arg0: first polynomial
    arg1: second polynomial
    """

    for i in range(PARAMS_N // 4):
        rx = base_multiplier(
            a[4 * i + 2], a[4 * i + 3],
            b[4 * i + 2], b[4 * i + 3],
            NTT_ZETAS[64 + i]
        )
        ry = base_multiplier(
            a[4 * i + 2], a[4 * i + 3],
            b[4 * i + 2], b[4 * i + 3],
            NTT_ZETAS[64 + i] * -1
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
    r = [0 for _ in range(PARAMS_N)]
    for i in range(PARAMS_N // 2):
        r[2 * i] = int16(((uint16(a[3 * i + 0]) >> 0) | (uint16(a[3 * i + 1]) << 8)) & 0xFFF)
        r[2 * i + 1] = int16(((uint16(a[3 * i + 1]) >> 4) | (uint16(a[3 * i + 2]) << 4)) & 0xFFF)
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
            mask = -1 * int16((msg[i] >> j) & 1)
            r[8 * i + j] = mask & (PARAMS_Q // 2)
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
            t = (((uint16(a[8 * i + j]) << 1) + uint16(PARAMS_Q / 2)) / uint16(PARAMS_Q)) & 1
            msg[i] |= byte(t << j)
    return msg


def poly_compress(a, k):
    """
    Compression and subsequent serialization of a polynomial

    arg0: polynomial
    arg1: value of PARAM_K
    """
    rr = 0
    r = []
    t = [0 for _ in range(8)]
    a = poly_conditional_sub_q(a)
    if k == 2 or k == 3:
        r = [0 for _ in range(COMPRESSED_BYTES_512)]
        for i in range(PARAMS_N // 8):
            for j in range(8):
                t[j] = byte(((uint16(a[8 * i + j]) << 4) + uint16(PARAMS_Q // 2)) // uint16(PARAMS_Q)) & 15
            r[rr + 0] = byte(t[0] | (t[1] << 4))
            r[rr + 1] = byte(t[2] | (t[3] << 4))
            r[rr + 2] = byte(t[4] | (t[5] << 4))
            r[rr + 3] = byte(t[6] | (t[7] << 4))
            rr = rr + 4
    else:
        r = [0 for _ in range(COMPRESSED_BYTES_1024)]
        for i in range(PARAMS_N // 8):
            for j in range(8):
                t[j] = byte(((uint32(a[8 * i + j]) << 5) + uint32(PARAMS_Q // 2)) // uint32(PARAMS_Q)) & 31
            r[rr + 0] = (t[0] >> 0) | (t[1] << 5)
            r[rr + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7)
            r[rr + 2] = (t[3] >> 1) | (t[4] << 4)
            r[rr + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6)
            r[rr + 4] = (t[6] >> 2) | (t[7] << 3)
            rr = rr + 5
    return r


def poly_decompress(a, k):
    """
    De-serialization and subsequent decompression of a polynomial;
    approximate inverse of poly_compress

    arg0: byte array
    arg1: value of PARAM_K
    """
    r = [0 for _ in range(384)]
    t = [0 for _ in range(8)]
    aa = 0
    if k == 2 or k == 3:
        for i in range(PARAMS_N // 2):
            r[2 * i + 0] = int16((((byte(a[aa]) & 15) * uint32(PARAMS_Q)) + 8) >> 4)
            r[2 * i + 1] = int16(((uint16(a[aa] >> 4) * uint16(PARAMS_Q)) + 8) >> 4)
            aa += 1
    else:
        for i in range(PARAMS_N // 8):
            t[0] = (a[aa + 0] >> 0);
            t[1] = byte(a[aa + 0] >> 5) | byte((a[aa + 1] << 3));
            t[2] = (a[aa + 1] >> 2);
            t[3] = byte((a[aa + 1] >> 7)) | byte((a[aa + 2] << 1));
            t[4] = byte((a[aa + 2] >> 4)) | byte((a[aa + 3] << 4));
            t[5] = (a[aa + 3] >> 1);
            t[6] = byte((a[aa + 3] >> 6)) | byte((a[aa + 4] << 2));
            t[7] = (a[aa + 4] >> 3);
            aa = aa + 5;
            for j in range(8):
                r[8 * i + j] = int16(((byte(t[j] & 31) * uint32(PARAMS_Q)) + 16) >> 5)
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
