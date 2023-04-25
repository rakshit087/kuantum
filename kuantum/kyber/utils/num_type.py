import numpy as np


# Convert a number to a byte representation
def byte(x):
    y = x & 0xff
    if y >= 2 ** 7:
        y -= 2 ** 8
    return y


# Convert a number to a signed 16-bit representation
def int16(x):
    y = x & 0xffff
    if y >= 2 ** 15:
        y -= 2 ** 16
    return y


# Convert a number to a signed 32-bit representation
def int32(x):
    y = x & 0xffffffff
    if y >= 2 ** 31:
        y -= 2 ** 32
    return y


def long64(x):
    y = x & 0xffffffffffffffff
    if y >= 2 ** 63:
        y -= 2 ** 64
    return y


# Convert a number to a unsigned 16-bit representation
def uint16(x):
    return np.uint16(x)


# Convert a number to a unsigned 32-bit representation
def uint32(x):
    return np.uint32(x)
