from kuantum.kyber.utils.constants import PARAMS_SYSTEM_BYTES, POLY_BYTES, PARAMS_Q, PARAMS_N
from kuantum.kyber.utils.constants import PARAMS_K_512, PARAMS_K_768, PARAMS_K_1024
from kuantum.kyber.utils.num_type import uint16, int16, byte
from kuantum.kyber.utils.ntt import ntt
from kuantum.kyber.utils.poly import get_noise_poly, poly_barret_reduce, poly_montgomery_reduce, poly_add, poly_to_bytes
from kuantum.kyber.utils.poly_vect import polyvec_pointwise_mul
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
        """
        Deterministically generate matrix A (or the transpose of A)
        from a seed. Entries of the matrix are polynomials that look
        uniformly random. Performs rejection sampling on output of
        a XOF

        arg0: seed
        arg1: boolean deciding whether A or A^T is generated
        """
        a = [[[0 for x in range(0, POLY_BYTES)]
              for y in range(0, self.k)] for z in range(0, self.k)]
        ctr = 0
        for i in range(self.k):
            transpose = [0, 0]
            for j in range(self.k):
                xof = SHAKE128.new()
                transpose[0] = byte(i)
                transpose[1] = byte(j)
                if transposed:
                    transpose[0] = byte(j)
                    transpose[1] = byte(i)
                seed_unsigned = [x & 0xff for x in seed]
                xof.update(bytearray(seed_unsigned)).update(bytearray(transpose))
                buf = xof.read(672)
                buf_signed = [byte(x) for x in buf]
                result = self.idcpa_rej_uniform(
                    buf_signed[504:672], 168, PARAMS_N
                )
                a[i][j] = result[0]
                ctr = result[1]
                while ctr < PARAMS_N:
                    missing, ctrn = self.idcpa_rej_uniform(
                        buf_signed[504:672], 168, PARAMS_N - ctr
                    )
                    for k in range(ctr, PARAMS_N):
                        a[i][j][k] = missing[k - ctr]
                    ctr = ctr + ctrn
        return a

    def idcpa_rej_uniform(self, buf, buf_len, req_len):
        '''
         Run rejection sampling on uniform random bytes to generate uniform random integers mod q

         arg0: byte array
         arg1: length of byte array
         arg2: requested number of 16-bit integers
        '''
        uniform_r = [0 for x in range(POLY_BYTES)]
        i, j = 0, 0

        while i < req_len and (j + 3) <= buf_len:
            d1 = (uint16((buf[j]) >> 0) | (uint16(buf[j+1]) << 8)) & 0xFFF
            d2 = (uint16((buf[j+1]) >> 4) | (uint16(buf[j+2]) << 4)) & 0xFFF
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
        noiseseed = [seed[i] for i in range(PARAMS_SYSTEM_BYTES, 2*PARAMS_SYSTEM_BYTES)]

        # generate matrix A
        A = self.gen_matrix(public_seed, False)
        s = [] # secret
        e = [] # noise
        nonce = 0

        for i in range(self.k):
            s.append(get_noise_poly(noiseseed, i, self.k))
            e.append(get_noise_poly(noiseseed, i+self.k, self.k))

        for i in range(self.k):
            s[i] = ntt(s[i])
            e[i] = ntt(e[i])

        for i in range(self.k):
            s[i] = poly_barret_reduce(s[i])

        pk = [0 for _ in range(self.k)]

        for i in range(self.k):
            pk[i] = poly_montgomery_reduce(polyvec_pointwise_mul(A[i], s, self.k))

        for i in range(self.k):
            pk[i] = poly_add(pk[i], e[i])
        
        for i in range(self.k):
            pk[i] = poly_barret_reduce(pk[i])

        keys = {
            'public_key': [],
            'secret_key': []
        }

        #Public Key
        pk_bytes = []
        for i in range(self.k):
            byte_array = poly_to_bytes(pk[i])
            for j in range(len(byte_array)):
                keys['public_key'].append(byte_array[j])

        # append public seed
        for i in range(len(public_seed)):
            keys['public_key'].append(public_seed[i])
        
        #Secret Key
        for i in range(self.k):
            byte_array = poly_to_bytes(s[i])
            for j in range(len(byte_array)):
                keys['secret_key'].append(byte_array[j])

        return keys


    def idcpa_enc(self):
        pass

    def idcpa_dec(self):
        pass