from kuantum.kyber.utils.num_type import int16, int32, uint32
from kuantum.kyber.utils.constants import PARAMS_Q_INV, PARAMS_Q


def montgomery_reduce(a: int) -> int:
    """
    computes 16-bit integer congruent to a * R^-1 mod q, where R=2^16

    arg0: 32-bit integer to be reduced
    return: 16-bit integer congruent to a * R^-1 mod q
    """
    t = int16(int32(a) * PARAMS_Q_INV)
    u = int32(t) * PARAMS_Q
    v = uint32(a - t)
    v = v >> 16
    return int16(v + u)


def barrett_reduce(a: int) -> int:
    """
    computes centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}

    arg0: 16 bit integer to be reduced
    return: 16-bit integer congruent to a mod q
    """
    v = int16(((1 << 26) + PARAMS_Q // 2) // PARAMS_Q)
    t = int16(int16(v * a) >> 26)
    t = int16(t * PARAMS_Q)
    return int16(a - t)
