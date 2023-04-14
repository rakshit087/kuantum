import numpy as np

class ByteOps:

    # returns a 24-bit unsigned integer loaded from byte x.
    def byte_to_24_bit_uint(self, byte):
        r = np.uint32(byte[0])
        r |= (np.uint32(byte[1]) << 8)
        r |= (np.uint32(byte[2]) << 16)
        return r
    
    # returns a 32-bit unsigned integer loaded from byte x.
    def byte_to_32_bit_uint(self, byte):
        r = np.uint32(byte[0])
        r = r | (np.uint32(byte[1]) << 8)
        r = r | (np.uint32(byte[2]) << 16)
        r = r | (np.uint32(byte[3]) << 24)
        return r
    
    # computes a polynomial with coefficients distributed
    # according to a centered binomial distribution with parameter eta,
    # given an array of uniformly random bytes.
    def gen_cbd_pol(self, buff, eta):
        pass

    # computes a Barrett reduction given a 16 bit integer
    def barrett_reduce(self, a):
        pass

    # computes a Montgomery reduction given a 32 bit integer
    # returns `a * R^-1 mod Q` where `R=2^16`
    def montgomery_reduce(self, a):
        pass
