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

def poly_decompress(a):
    pass

def get_noise_poly(seed, nonce, k):
    pass

def gen_prf_byte_array():
    pass

def poly_csubq(a):
    pass