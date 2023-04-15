from utils.constants import PARAMS_SYSTEM_BYTES
from utils.constants import PARAMS_K_512, PARAMS_K_768, PARAMS_K_1024
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_512, SHAKE128

class IDCPA:

    def __init__(self, type='kyber768'):
        self.type = type
        if type == 'kyber512':
            self.k = PARAMS_K_512
        if type == 'kyber768':
            self.k = PARAMS_K_768
        if type == 'kyber1024':
            self.k = PARAMS_K_1024

    def gen_matrix(self, seed, transposed):
        a = []


    def idcpa_rej_uniform(self):
        pass

    def idcpa_gen_keypair(self):
        # random bytes for seed
        rnd = get_random_bytes(PARAMS_SYSTEM_BYTES)

        # hash the random bytes
        h = SHA3_512.new()
        h.update(rnd)

        # generate seed, public seed and noiseseed
        seed = h.digest()
        public_seed = [seed[i] for i in range(PARAMS_SYSTEM_BYTES)]
        noiseseed = [seed[i] for i in range(PARAMS_SYSTEM_BYTES, 2*PARAMS_SYSTEM_BYTES)]

        # generate matrix A
        A = self.gen_matrix(public_seed, False)


    def idcpa_enc(self):
        pass

    def idcpa_dec(self):
        pass