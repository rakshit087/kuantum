import numpy as np

def array_compare(a,  b):
    if a.shape != b.shape:
        return False
    if not np.allclose(a, b):
        return False
    return True
    