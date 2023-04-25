from kuantum.kyber.utils.reduce import barrett_reduce, montgomery_reduce

pairs = [[3560835, 1114],
         [3067203, -1283],
         [133692, 25],
         [7129383, 757],
         [6142119, -708],
         [1110672, 1232],
         [6836289, 62],
         [7805556, -589],
         [6887709, 1352],
         [7062537, -920]]

for a, t in pairs:
    res = montgomery_reduce(a)
    try:
        assert (t == res)
        print("OK ✅")
    except AssertionError:
        print(f"Failed for {a} -> {res} != {t}")

pairs = [[3862, 533],
         [-1343, 1986],
         [-1880, 1449],
         [1293, 1293],
         [1186, 1186],
         [-1890, 1439],
         [4800, 1471]]

for a, t in pairs:
    res = barrett_reduce(a)
    try:
        assert (t == res)
        print("OK ✅")
    except AssertionError:
        print(f"Failed for {a} -> {res} != {t}")
