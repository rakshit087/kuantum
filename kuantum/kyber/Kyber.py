from kuantum.kyber.utils.constants import PARAMS_K_512, PARAMS_K_768, PARAMS_K_1024, POLY_BYTES
from kuantum.kyber.utils.num_type import uint16, int16, byte
from kuantum.kyber.IDCPA import IDCPA
from Crypto.Hash import SHA3_256, SHA3_512, SHAKE256
from Crypto.Random import get_random_bytes

POLY_VEC_BYTES_K512 = 2 * POLY_BYTES
POLY_VEC_BYTES_K768 = 3 * POLY_BYTES
POLY_VEC_BYTES_K1024 = 4 * POLY_BYTES

IDCPA_PK_BYTES_512 = POLY_VEC_BYTES_K512 + 32
IDCPA_PK_BYTES_768 = POLY_VEC_BYTES_K768 + 32
IDCPA_PK_BYTES_1024 = POLY_VEC_BYTES_K1024 + 32

IDCPA_SK_BYTES_512 = 2 * POLY_BYTES
IDCPA_SK_BYTES_768 = 3 * POLY_BYTES
IDCPA_SK_BYTES_1024 = 4 * POLY_BYTES

KYBER_SK_BYTES_512 = POLY_VEC_BYTES_K512 + ((POLY_VEC_BYTES_K512 + 32) + 2 * 32)
KYBER_SK_BYTES_768 = POLY_VEC_BYTES_K768 + ((POLY_VEC_BYTES_K768 + 32) + 2 * 32)
KYBER_SK_BYTES_1024 = POLY_VEC_BYTES_K1024 + ((POLY_VEC_BYTES_K1024 + 32) + 2 * 32)


class Kyber:

    def __init__(self, level):
        self.type = level
        if level == 'kyber512':
            self.k = PARAMS_K_512
        if level == 'kyber768':
            self.k = PARAMS_K_768
        if level == 'kyber1024':
            self.k = PARAMS_K_1024
        self.idcpa = IDCPA(level)

    def gen_keypair(self):
        keys = self.idcpa.idcpa_gen_keypair()
        pk = keys['public_key']
        sk = keys['secret_key']

        md = SHA3_256.new()
        md.update(bytearray([x & 0xff for x in pk]))
        h_pk = md.digest()
        h_pk = [byte(x) for x in h_pk]
        z = get_random_bytes(32)
        z = [byte(x) for x in z]

        kyber_keys = {
            'public_key': pk,
            'secret_key': sk[:] + pk[:] + h_pk[:] + z[:]
        }

        return kyber_keys

    def encrypt(self, public_key, msg=None):
        if msg is not None and len(msg) != 32:
            raise ValueError('Message must be 32 bytes long')
        if msg is None:
            msg = get_random_bytes(32)

        # hash msg with SHA3-256
        md = SHA3_256.new()
        md.update(bytearray([x & 0xff for x in msg]))
        h_msg = md.digest()
        h_msg = [byte(x) for x in h_msg]

        # hash public key with SHA3-256
        md = SHA3_256.new()
        md.update(bytearray([x & 0xff for x in public_key]))
        h_pk = md.digest()
        h_pk = [byte(x) for x in h_pk]

        # hash h_msg and h_pk with SHA3-512
        md512 = SHA3_512.new()
        md512.update(bytearray([x & 0xff for x in h_msg + h_pk]))
        h_msg_pk = md512.digest()
        h_msg_pk = [byte(x) for x in h_msg_pk]

        kr1 = h_msg_pk[:32]
        kr2 = [h_msg_pk[i + 32] for i in range(0, len(h_msg_pk) - 32)]

        # generate ciphertext
        ct = self.idcpa.idcpa_enc(public_key, h_msg, kr2)

        # hash cypher text with SHA-256
        md = SHA3_256.new()
        md.update(bytearray([x & 0xff for x in ct]))
        h_ct = md.digest()
        h_ct = [byte(x) for x in h_ct]

        # hash kr1 and h_ct with SHAKE-256
        md_shake = SHAKE256.new()
        md_shake.update(bytearray([x & 0xff for x in kr1 + h_ct]))
        shared_secret = md_shake.read(32)
        shared_secret = [byte(x) for x in shared_secret]

        return {
            'ciphertext': ct,
            'shared_secret': shared_secret
        }

    def decrypt(self, cipher_text, private_key):
        idcpa_private_key = None
        idcpa_public_key = None
        if self.k == 2:
            idcpa_private_key = private_key[0: IDCPA_SK_BYTES_512]
            idcpa_public_key = private_key[IDCPA_SK_BYTES_512:IDCPA_SK_BYTES_512 + IDCPA_PK_BYTES_512]
            h = private_key[KYBER_SK_BYTES_512 - 2 * 32:KYBER_SK_BYTES_512 - 32]
            z = private_key[KYBER_SK_BYTES_512 - 32:]

        if self.k == 3:
            idcpa_private_key = private_key[0: IDCPA_SK_BYTES_768]
            idcpa_public_key = private_key[IDCPA_SK_BYTES_768:IDCPA_SK_BYTES_768 + IDCPA_PK_BYTES_768]
            h = private_key[KYBER_SK_BYTES_768 - 2 * 32:KYBER_SK_BYTES_768 - 32]
            z = private_key[KYBER_SK_BYTES_768 - 32:]

        if self.k == 4:
            idcpa_private_key = private_key[0: IDCPA_SK_BYTES_1024]
            idcpa_public_key = private_key[IDCPA_SK_BYTES_1024:IDCPA_SK_BYTES_1024 + IDCPA_PK_BYTES_1024]
            h = private_key[KYBER_SK_BYTES_1024 - 2 * 32:KYBER_SK_BYTES_1024 - 32]
            z = private_key[KYBER_SK_BYTES_1024 - 32:]

        # idcpa decrypt
        msg = self.idcpa.idcpa_dec(cipher_text, idcpa_private_key)

        # hash msg + pk_h with SHA3-512
        md = SHA3_512.new()
        md.update(bytearray([x & 0xff for x in msg + h]))
        h_msg_pk = md.digest()
        h_msg_pk = [byte(x) for x in h_msg_pk]
        k = h_msg_pk[:32]
        r = h_msg_pk[-32:]

        # idcpa encrypt
        ct = self.idcpa.idcpa_enc(idcpa_public_key, msg, r)

        # hash ct with SHA3-256
        md = SHA3_256.new()
        md.update(bytearray([x & 0xff for x in cipher_text]))
        h_ct = md.digest()
        h_ct = [byte(x) for x in h_ct]

        if ct == cipher_text:
            temp_buf = k + h_ct
        else:
            temp_buf = z[:] + h_ct

        # hash temp_buf with SHAKE-256
        md_shake = SHAKE256.new()
        md_shake.update(bytearray([x & 0xff for x in temp_buf]))
        shared_secret = md_shake.read(32)
        return [byte(x) for x in shared_secret]
