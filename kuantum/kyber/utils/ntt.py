from kuantum.kyber.utils.num_type import  int16, int32
from kuantum.kyber.utils.reduce import montgomery_reduce, barrett_reduce
from kuantum.kyber.utils.constants import NTT_ZETAS, NTT_ZETAS_INV
import numpy as np


def ntt(r):
    """
    Inplace number-theoretic transform (NTT) in Rq.
    input is in standard order, output is in a bit reversed order

    arg0: array of 16-bit integers
    return: bit-inverse array of 16-bit integers
    """
    k = 1
    l = 128
    # 128, 64, 32, 16, 8, 4, 2
    while l >= 2:
        start = 0
        while start < 256:
            zeta = NTT_ZETAS[k]
            k = k + 1
            j = start
            # for each element in the subsections (128, 64, 32, 16, 8, 4, 2) starting at an offset
            while j < start + l:
                # compute the modular multiplication of the zeta and each element in the subsection
                t = montgomery_reduce(zeta * r[j + l])
                # overwrite each element in the subsection as the opposite subsection element minus t
                r[j + l] = int16(r[j] - t)
                # add t back again to the opposite subsection
                r[j] = int16(r[j] + t)
                j += 1
            start = j + l
        l >>= 1
    return r


def inv_ntt(r):
    """
    Inplace inverse number-theoretic transform in Rq and
    multiplication by Montgomery factor 2^16.

    arg0: bit-inverse array of 16-bit integers
    return: standard array of 16-bit integers
    """
    k = 0
    l = 2
    while l <= 128:
        start = 0
        while start < 256:
            zeta = NTT_ZETAS_INV[k]
            k = k + 1
            j = start
            while j < (start + l):
                t = r[j]
                t_rjl = int16(t + r[j + l])
                r[j] = barrett_reduce(t_rjl)
                r[j + l] = int16(t - r[j + l])
                r[j + l] = montgomery_reduce(zeta * r[j + l])
                j += 1
            start = j + l
        l <<= 1
    for j in range(0, 256):
        r[j] = montgomery_reduce(r[j] * NTT_ZETAS_INV[127])
    return r


def base_multiplier(a0, a1, b0, b1, zeta):
    """
    Multiplication of polynomials in Zq[X]/(X^2-zeta)
    used for multiplication of elements in Rq in NTT domain

    arg0: output polynomial
    arg1: first factor
    arg2: second factor
    arg3: integer defining the reduction polynomial
    """
    r = [0 for _ in range(0, 2)]
    r[0] = montgomery_reduce(a1 * b1)
    r[0] = montgomery_reduce(r[0] * zeta)
    r[0] = int16(r[0] + montgomery_reduce(a0 * b0))
    r[1] = montgomery_reduce(a0 * b1)
    r[1] = int16(r[1] + montgomery_reduce(a1 * b0))
    return r
