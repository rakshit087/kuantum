from constants import PARAMS_N, PARAMS_Q, COMPRESSED_BYTES_512, COMPRESSED_BYTES_1024
from num_type import int16, int32, uint16, uint32, byte
from types import List

def poly_add(a, b):
    '''
    Add two polynomials; no modular reduction is performed

    arg0: first polynomial
    arg1: second polynomial 
    '''
    c = [a[i] + b[i] for i in range(len(a))]
    return c

def poly_sub(a, b):
    '''
    Subtract two polynomials; no modular reduction is performed

    arg0: first polynomial
    arg1: second polynomial
    '''
    c = [a[i] - b[i] for i in range(len(a))]
    return c

def poly_conditional_sub_q(r: List[int]):
    '''
    Apply the conditional subtraction of Q (KyberParams) to each coefficient of a

    arg0: polynomial
    '''
    for i in range(PARAMS_N):
        r[i] -= int16(PARAMS_Q)
        r[i] += (r[i] >> 31) & int16(PARAMS_Q)
    return r

def poly_barret_reduce():
    pass


def poly_montgomery_reduce():
    pass


def poly_base_mul():
    pass


def poly_to_bytes(a):
    '''
    Serialize a polynomial to a byte array.

    arg0: polynomial
    '''
    pass


def poly_from_bytes(a):
    '''
    Deserialize a polynomial from a byte array.

    arg0: byte array
    '''
    pass


def poly_from_msg(a):
    '''
    Convert a 32-byte message to a polynomial.

    arg0: 32-byte message
    '''
    pass


def poly_to_msg(a):
    '''
    Convert a polynomial to a 32-byte message.

    arg0: polynomial
    '''
    pass


def poly_compress(a, k):
    '''
    Compression and subsequent serialization of a polynomial

    arg0: polynomial
    arg1: value of PARAM_K
    '''
    rr = 0
    r = []
    t = [0 for x in range(8)]
    a = poly_csubq(a)
    if k == 2 or k == 3:
        r = [0 for _ in range(COMPRESSED_BYTES_512)]
        for i in range(PARAMS_N // 8):
            for j in range(8):
                t[j] = byte(((uint16(a[8*i+j])<<4)+uint16(PARAMS_Q/2))/uint16(PARAMS_Q)) & 15
            r[rr+0] = byte(t[0] | (t[1] << 4))
            r[rr+1] = byte(t[2] | (t[3] << 4))
            r[rr+2] = byte(t[4] | (t[5] << 4))
            r[rr+3] = byte(t[6] | (t[7] << 4))
            rr = rr + 4
    else:
        r = [0 for _ in range(COMPRESSED_BYTES_1024)]
        for i in range(PARAMS_N // 8):
            for j in range(8):
                t[j] = byte(((uint32(a[8*i+j])<<5)+uint32(PARAMS_Q/2))/uint32(PARAMS_Q)) & 31
            r[rr+0] = (t[0] >> 0) | (t[1] << 5)
            r[rr+1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7)
            r[rr+2] = (t[3] >> 1) | (t[4] << 4)
            r[rr+3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6)
            r[rr+4] = (t[6] >> 2) | (t[7] << 3)
            rr = rr + 5
    return r

def poly_decompress(a, k):
    '''
    De-serialization and subsequent decompression of a polynomial;
    approximate inverse of poly_compress

    arg0: byte array
    arg1: value of PARAM_K
    '''
    r = [0 for x in range(384)]
    t = [0 for x in range(8)]
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
    pass


def gen_prf_byte_array():
    pass


def poly_csubq(a):
    pass
