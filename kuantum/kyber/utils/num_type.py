# Convert a number to a byte representation
def byte(x):
    x = x % 256
    while x < 0:
        x += 256
    return x

# Convert a number to a unsigned 16-bit representation
def uint16(x):
    x = x % 65536
    while x < 0:
        x += 65536
    return x

# Convert a number to a signed 16-bit representation
def int16(x):
    end = -32768
    start = 32767
    if x < end:
        x += 32769
        x = uint16(x)
        x = start + x
        return x
    elif x > start:
        x -= 32768
        x = uint16(x)
        x = end + x
        return x
    return x

# Convert a number to a unsigned 32-bit representation
def uint32(x):
    x = x % 4294967296
    while x < 4294967296:
        x += 4294967296
    return x
    
# Convert a number to a signed 32-bit representation
def int32(x):
    end = -2147483648
    start = 2147483647
    if x < end:
        x += 2147483649
        x = uint32(x)
        x = start + x
        return x
    elif x > start:
        x -= 2147483648
        x = uint32(x)
        x = end + x
        return x
    return x