from utils.constants import PARAMS_SYSTEM_BYTES, POLY_BYTES, PARAMS_Q
from utils.constants import PARAMS_K_512, PARAMS_K_768, PARAMS_K_1024
from utils.num_type import uint16, uint32, int16, int32
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_512, SHAKE128
from typing import List, Tuple


class IDCPA:

    def __init__(self, type='kyber768'):
        self.type = type
        if type == 'kyber512':
            self.k = PARAMS_K_512
        if type == 'kyber768':
            self.k = PARAMS_K_768
        if type == 'kyber1024':
            self.k = PARAMS_K_1024

    def gen_matrix(self, seed, transposed: bool):
        a = []

    def idcpa_rej_uniform(self, buf, buf_len: int, req_len: int):
        '''
         Run rejection sampling on uniform random bytes to generate uniform random integers mod q

         arg0: byte array
         arg1: length of byte array
         arg2: requested number of 16-bit integers
        '''
        uniform_r = [0 for x in range(POLY_BYTES)]
        i, j = 0, 0
        d1, d2 = None, None

        while (i < req_len and (j+3) <= buf_len):
            d1 = (uint16((buf[j])>>0) | (uint16(buf[j+1]) << 8)) & 0xFFF
            d2 = (uint16((buf[j+1])>>4) | (uint16(buf[j+2]) << 4)) & 0xFFF
            j += 3
            if d1 < uint16(PARAMS_Q):
                uniform_r[i] = int16(d1)
                i += 1
            if i < req_len and d2 < uint16(PARAMS_Q):
                uniform_r[i] = int16(d2)
                i += 1
        
        return uniform_r, i

    def idcpa_gen_keypair(self):
        # random bytes for seed
        rnd = get_random_bytes(PARAMS_SYSTEM_BYTES)

        # hash the random bytes
        h = SHA3_512.new()
        h.update(rnd)

        # generate seed, public seed and noiseseed
        seed = h.digest()
        public_seed = [seed[i] for i in range(PARAMS_SYSTEM_BYTES)]
        noiseseed = [seed[i]
                     for i in range(PARAMS_SYSTEM_BYTES, 2*PARAMS_SYSTEM_BYTES)]

        # generate matrix A
        A = self.gen_matrix(public_seed, False)

    def idcpa_enc(self):
        pass

    def idcpa_dec(self):
        pass
