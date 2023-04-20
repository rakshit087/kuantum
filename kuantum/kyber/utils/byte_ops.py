from kuantum.kyber.utils.num_type import int16, int32, uint32
from kuantum.kyber.utils.constants import PARAMS_N, PARAMS_ETA_1, PARAMS_ETA_2, POLY_BYTES


def load24_bit(byte):
    '''
    load 3 bytes into a 32-bit integer needed for Kyber 512
    arg0: input byte array
    return:  32-bit unsigned integer 
    '''
    r = int32(byte[0])
    r |= (int32(byte[1]) << 8)
    r |= (int32(byte[2]) << 16)
    return r


def load32_bit(byte):
    '''
    load 4 bytes into a 32-bit integer needed for Kyber 768 
    and Kyber 1024
    
    arg0: input byte array
    return:  32-bit unsigned integer
    '''
    r = uint32(byte[0])
    r = r | (uint32(byte[1]) << 8)
    r = r | (uint32(byte[2]) << 16)
    r = r | (uint32(byte[3]) << 24)
    return r


def gen_cbd_pol(buff, eta):
    '''
    compute polynomial with coefficients distributed according to
    a centered binomial distribution 

    arg0: array of uniformly random bytes
    arg1: eta = 2 for Kyber 512 and eta = 3 Kyber 768 / Kyber 1024
    
    return: array with coefficients
    '''
    r = [0 for i in range(POLY_BYTES)]
    if eta == 2:
        for i in range(0, PARAMS_N // 4):
            t = load24_bit(buff[3 * i:])
            d = t & 0x00249249
            d += ((t >> 1) & 0x00249249)
            d += ((t >> 2) & 0x00249249)
            for j in range(0, 4):
                a = int16((d >> (6 * j + 0)) & 0x7)
                b = int16((d >> (6 * j + PARAMS_ETA_1)) & 0x7)
                r[4 * i + j] = (a - b)
    else:
        for i in range(0, PARAMS_N // 8):
            t = load32_bit(buff[4 * i:])
            d = t & 0x55555555
            d = d + ((t >> 1) & 0x55555555)
            for j in range(0, 8):
                a = int16((d >> (4 * j + 0)) & 0x3)
                b = int16((d >> (4 * j + PARAMS_ETA_2)) & 0x3)
                r[8 * i + j] = (a - b)
    return r