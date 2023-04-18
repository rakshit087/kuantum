from constants import PARAMS_N, PARAMS_Q
from num_type import int16, int32, uint16, uint32, byte

# adds two polynomials.


def poly_add(a, b):
    pass

# subtracts two polynomials.


def poly_sub():
    pass


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


def poly_compress(a):
    pass


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
