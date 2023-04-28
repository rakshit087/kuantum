from kuantum.kyber.utils.constants import PARAMS_SYSTEM_BYTES, POLY_BYTES, PARAMS_Q, PARAMS_N
from kuantum.kyber.utils.constants import PARAMS_K_512, PARAMS_K_768, PARAMS_K_1024
from kuantum.kyber.utils.num_type import uint16, int16, byte, int32
from kuantum.kyber.utils.ntt import ntt, inv_ntt
from kuantum.kyber.utils.poly import *
from kuantum.kyber.utils.poly_vect import *
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_512, SHAKE128
from typing import List, Dict

POLYVEC_BYTES_512 = 2 * POLY_BYTES
POLYVEC_BYTES_768 = 3 * POLY_BYTES
POLYVEC_BYTES_1024 = 4 * POLY_BYTES

POLY_COMPRESSED_BYTES_512 = 128
POLY_COMPRESSED_BYTES_768 = 128
POLY_COMPRESSED_BYTES_1024 = 160

POLYVEC_COMPRESSED_BYTES_512 = 320 * 2
POLYVEC_COMPRESSED_BYTES_768 = 320 * 3
POLYVEC_COMPRESSED_BYTES_1024 = 352 * 4


class IDCPA:

    def __init__(self, level='kyber768'):
        self.type = level
        if level == 'kyber512':
            self.k = PARAMS_K_512
        if level == 'kyber768':
            self.k = PARAMS_K_768
        if level == 'kyber1024':
            self.k = PARAMS_K_1024

    def gen_matrix(self, seed: List[int], transposed: bool) -> List[List[int]]:
        """
        Deterministically generate matrix A (or the transpose of A)
        from a seed. Entries of the matrix are polynomials that look
        uniformly random. Performs rejection sampling on output of
        a XOF

        arg0: seed
        arg1: boolean deciding whether A or A^T is generated
        """
        a = [[[ 0 for _ in range(POLY_BYTES)] for _ in range(self.k)] for _ in range(self.k)]
        for i in range(self.k):
            a[i] = [[ 0 for x in range(0, POLY_BYTES) ] for y in range(0, self.k)]
            for j in range(self.k):
                xof = SHAKE128.new()
                seed_unsigned = [x & 0xff for x in seed]
                xof.update(bytearray(seed_unsigned))
                ij = [0, 0]
                if transposed:
                    ij[0] = byte(i)
                    ij[1] = byte(j)
                else:
                    ij[0] = byte(j)
                    ij[1] = byte(i)
                xof.update(bytearray(ij))
                buf = xof.read(672)
                buf_signed = [byte(x) for x in buf]
                uniform_r, uniform_i = self.idcpa_rej_uniform(buf_signed[0:504], 504, PARAMS_N)
                a[i][j] = uniform_r
                while uniform_i < PARAMS_N:
                    missing, ctrn = self.idcpa_rej_uniform(buf_signed[504:672], 168, PARAMS_N - uniform_i)
                    for k in range(uniform_i, PARAMS_N):
                        a[i][j][k] = missing[k - uniform_i]
                    uniform_i = uniform_i + ctrn
        return a

    def idcpa_rej_uniform(self, buf, buf_len, req_len):
        """
         Run rejection sampling on uniform random bytes to generate uniform random integers mod q

         arg0: byte array
         arg1: length of byte array
         arg2: requested number of 16-bit integers
        """
        uniform_r = [0 for _ in range(POLY_BYTES)]
        i, j = 0, 0

        while i < req_len and (j + 3) <= buf_len:
            d1 = int32((((int32 (buf[j] & 0xFF)) >> 0) | ((int32 (buf[j + 1] & 0xFF)) << 8)) & 0xFFF)
            d2 = int32 ((((int32 (buf[j + 1] & 0xFF)) >> 4) | ((int32 (buf[j + 2] & 0xFF)) << 4)) & 0xFFF)
            j += 3
            if d1 < int32(PARAMS_Q):
                uniform_r[i] = int16(d1)
                i += 1
            if i < req_len and d2 < int32(PARAMS_Q):
                uniform_r[i] = int16(d2)
                i += 1

        return uniform_r, i

    def idcpa_gen_keypair(self) -> Dict:
        """
        Generate public and private key for the ID-CPA scheme

        Returns: public key, private key
        """
        # random bytes for seed
        rnd = get_random_bytes(PARAMS_SYSTEM_BYTES)

        # hash the random bytes
        h = SHA3_512.new()
        h.update(rnd)

        # generate seed, public seed and noiseseed
        seed = h.digest()
        public_seed = [seed[i] for i in range(PARAMS_SYSTEM_BYTES)]
        noiseseed = [seed[i] for i in range(PARAMS_SYSTEM_BYTES, 2 * PARAMS_SYSTEM_BYTES)]

        # generate matrix A
        A = self.gen_matrix(public_seed, False)
        s = []  # secret
        e = []  # noise
        nonce = 0

        for i in range(self.k):
            s.append(get_noise_poly(noiseseed, i, self.k))
            e.append(get_noise_poly(noiseseed, i + self.k, self.k))

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

        # Public Key
        for i in range(self.k):
            byte_array = poly_to_bytes(pk[i])
            for j in range(len(byte_array)):
                keys['public_key'].append(byte_array[j])

        # append public seed
        for i in range(len(public_seed)):
            keys['public_key'].append(public_seed[i])

        # Secret Key
        for i in range(self.k):
            byte_array = poly_to_bytes(s[i])
            for j in range(len(byte_array)):
                keys['secret_key'].append(byte_array[j])

        return keys

    def idcpa_enc(self, public_key: List[int], msg: List[int], coins: List[int]) -> List[int]:
        """
        Encrypt the given message using the Kyber public-key encryption scheme

        arg0: Public Key
        arg1: Message
        arg2: Coins
        """
        pk = []
        k = poly_from_msg(msg)
        for i in range(self.k):
            start = i * POLY_BYTES
            end = (i + 1) * POLY_BYTES
            pk.append(poly_from_bytes(public_key[start: end]))
        if self.k == 2:
            seed = public_key[POLYVEC_BYTES_512: POLYVEC_BYTES_512 + 32]
        elif self.k == 3:
            seed = public_key[POLYVEC_BYTES_768: POLYVEC_BYTES_768 + 32]
        else:
            seed = public_key[POLYVEC_BYTES_1024: POLYVEC_BYTES_1024 + 32]

        at = self.gen_matrix(seed, True)
        sp = []
        ep = []
        for i in range(self.k):
            sp.append(get_noise_poly(coins, i, self.k))
            ep.append(get_noise_poly(coins, i + self.k, 3))
        epp = get_noise_poly(coins, self.k * 3, 3)
        for i in range(self.k):
            sp[i] = ntt(sp[i])
        for i in range(self.k):
            sp[i] = poly_barret_reduce(sp[i])
        bp = []
        for i in range(self.k):
            bp.append(polyvec_pointwise_mul(at[i], sp, self.k))
        v = polyvec_pointwise_mul(pk, sp, self.k)
        bp = polyvec_invntt(bp, self.k)
        v = inv_ntt(v)
        bp = polyvec_add(bp, ep, self.k)
        v = poly_add(v, epp)
        v = poly_add(v, k)
        bp = polyvec_barret_reduce(bp, self.k)
        v = poly_barret_reduce(v)
        b_compressed = polyvec_compress(bp, self.k)
        v_compressed = poly_compress(v, self.k)
        return b_compressed + v_compressed

    def idcpa_dec(self, cipher_text: List[int], private_key: List[int]) -> List[int]:
        """
        Decrypt the given cipher text using the Kyber public-key encryption scheme

        arg0: Cipher Text
        arg1: Private Key
        """
        if self.k == 2:
            bp_end_index = POLYVEC_COMPRESSED_BYTES_512
            v_end_index = bp_end_index + POLY_COMPRESSED_BYTES_512
        elif self.k == 3:
            bp_end_index = POLYVEC_COMPRESSED_BYTES_768
            v_end_index = bp_end_index + POLY_COMPRESSED_BYTES_768
        else:
            bp_end_index = POLYVEC_COMPRESSED_BYTES_1024
            v_end_index = bp_end_index + POLY_COMPRESSED_BYTES_1024

        bp = polyvec_decompress(cipher_text[:bp_end_index], self.k)
        v = poly_decompress(cipher_text[bp_end_index: v_end_index], self.k)

        private_key_polyvec = polyvec_from_bytes(private_key, self.k)
        bp = polyvec_ntt(bp, self.k)
        mp = polyvec_pointwise_mul(private_key_polyvec, bp, self.k)
        mp = inv_ntt(mp)
        mp = poly_sub(v, mp)
        mp = poly_barret_reduce(mp)
        return poly_to_msg(mp)
