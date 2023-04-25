from kuantum.kyber.utils.constants import POLY_BYTES, PARAMS_N, PARAMS_Q
from kuantum.kyber.utils.num_type import uint16, uint32, int16, byte, long64
from kuantum.kyber.utils.poly import poly_barret_reduce, poly_from_bytes, poly_conditional_sub_q, poly_add, \
    poly_base_mul
from kuantum.kyber.utils.ntt import inv_ntt, ntt
from typing import List
import numpy as np

POLYVEC_COMPRESSED_BYTES_512 = 640
POLYVEC_COMPRESSED_BYTES_768 = 960
POLYVEC_COMPRESSED_BYTES_1024 = 1408


def polyvec_from_bytes(a, k):
    r = [[0 for _ in range(0, POLY_BYTES)] for _ in range(0, k)]
    for i in range(k):
        start = i * POLY_BYTES
        end = (i + 1) * POLY_BYTES
        r[i] = poly_from_bytes(a[start:end])
    return r


def polyvec_to_bytes(a):
    pass


def polyvec_compress(a, k):
    rr = 0
    if k == 2:
        r = [0 for _ in range(POLYVEC_COMPRESSED_BYTES_512)]
    elif k == 3:
        r = [0 for _ in range(POLYVEC_COMPRESSED_BYTES_768)]
    else:
        r = [0 for _ in range(POLYVEC_COMPRESSED_BYTES_1024)]

    if k == 2 or k == 3:
        t = [0 for x in range(4)]
        for i in range(k):
            for j in range(PARAMS_N // 4):
                for k in range(4):
                    t[k] = uint16((((uint32(a[i][4 * j + k]) << 10) + uint32(PARAMS_Q // 2)) // uint32(PARAMS_Q)) & 0x3ff)
                r[rr + 0] = byte(t[0] >> 0)
                r[rr + 1] = byte((t[0] >> 8) | (t[1] << 2))
                r[rr + 2] = byte((t[1] >> 6) | (t[2] << 4))
                r[rr + 3] = byte((t[2] >> 4) | (t[3] << 6))
                r[rr + 4] = byte((t[3] >> 2))
                rr = rr + 5
    else:
        t = [0 for x in range(8)]
        for i in range(k):
            for j in range(PARAMS_N // 8):
                for k in range(8):
                    t[k] = uint16((((uint32(a[i][8 * j + k]) << 11) + uint32(PARAMS_Q / 2)) / uint32(PARAMS_Q)) & 0x7ff)
                    r[rr + 0] = byte((t[0] >> 0))
                    r[rr + 1] = byte((t[0] >> 8) | (t[1] << 3))
                    r[rr + 2] = byte((t[1] >> 5) | (t[2] << 6))
                    r[rr + 3] = byte((t[2] >> 2))
                    r[rr + 4] = byte((t[2] >> 10) | (t[3] << 1))
                    r[rr + 5] = byte((t[3] >> 7) | (t[4] << 4))
                    r[rr + 6] = byte((t[4] >> 4) | (t[5] << 7))
                    r[rr + 7] = byte((t[5] >> 1))
                    r[rr + 8] = byte((t[5] >> 9) | (t[6] << 2))
                    r[rr + 9] = byte((t[6] >> 6) | (t[7] << 5))
                    r[rr + 10] = byte((t[7] >> 3))
                    rr = rr + 11
    return r


def polyvec_decompress(a, k):
    r = [[0 for x in range(0, POLY_BYTES)] for y in range(0, k)]
    aa = 0
    t = []
    if k == 2 or k == 3:
        t = [0 for x in range(4)]
        for i in range(k):
            for j in range(PARAMS_N // 4):
                t[0] = ((a[aa + 0] & 0xFF) >> 0) | ((a[aa + 1] & 0xFF) << 8)
                t[1] = ((a[aa + 1] & 0xFF) >> 2) | ((a[aa + 2] & 0xFF) << 6)
                t[2] = ((a[aa + 2] & 0xFF) >> 4) | ((a[aa + 3] & 0xFF) << 4)
                t[3] = ((a[aa + 3] & 0xFF) >> 6) | ((a[aa + 4] & 0xFF) << 2)
                aa = aa + 5
                for k in range(4):
                    r[i][4 * j + k] = int16 (( (t[k] & 0x3FF) *  (PARAMS_Q) + 512) >> 10)
    else:
        t = [0 for x in range(4)]
        for i in range(k):
            for j in range(PARAMS_N // 8):
                t[0] = (((a[aa + 0] & 0xff) >> 0) | ((a[aa + 1] & 0xff) << 8))
                t[1] = (((a[aa + 1] & 0xff) >> 3) | ((a[aa + 2] & 0xff) << 5))
                t[2] = (((a[aa + 2] & 0xff) >> 6) | ((a[aa + 3] & 0xff) << 2) | ((a[aa + 4] & 0xff) << 10))
                t[3] = (((a[aa + 4] & 0xff) >> 1) | ((a[aa + 5] & 0xff) << 7))
                t[4] = (((a[aa + 5] & 0xff) >> 4) | ((a[aa + 6] & 0xff) << 4))
                t[5] = (((a[aa + 6] & 0xff) >> 7) | ((a[aa + 7] & 0xff) << 1) | ((a[aa + 8] & 0xff) << 9))
                t[6] = (((a[aa + 8] & 0xff) >> 2) | ((a[aa + 9] & 0xff) << 6))
                t[7] = (((a[aa + 9] & 0xff) >> 5) | ((a[aa + 10] & 0xff) << 3))
                aa = aa + 11
                for k in range(8):
                    r[i][8 * j + k] = int16((long64(t[k] & 0x7FF) * long64 (PARAMS_Q) + 1024) >> 11)
    return r


def polyvec_pointwise_mul(a: List[int], b: List[int], k: int):
    """
    Point-wise multiplies elements of the given polynomial-vectors ,
    accumulates the results , and then multiplies by 2^-16
    """
    r = poly_base_mul(a[0], b[0])
    for i in range(1, k):
        t = poly_base_mul(a[i], b[i])
        r = poly_add(r, t)
    return poly_barret_reduce(r)


def polyvec_csubq(a, k):
    for i in range(k):
        a[i] = poly_conditional_sub_q(a[i])
    return a


def polyvec_ntt(a, k):
    for i in range(k):
        a[i] = ntt(a[i])
    return a


def polyvec_invntt(a, k):
    for i in range(k):
        a[i] = inv_ntt(a[i])
    return a


def polyvec_barret_reduce(r, k):
    for i in range(k):
        r[i] = poly_barret_reduce(r[i])
    return r


def polyvec_add(a: List[List[int]], b: List[List[int]], k: int):
    for i in range(k):
        a[i] = poly_add(a[i], b[i])
    return a


__all__ = [
    "polyvec_from_bytes",
    "polyvec_compress",
    "polyvec_decompress",
    "polyvec_pointwise_mul",
    "polyvec_csubq",
    "polyvec_ntt",
    "polyvec_invntt",
    "polyvec_barret_reduce",
    "polyvec_add",
]
