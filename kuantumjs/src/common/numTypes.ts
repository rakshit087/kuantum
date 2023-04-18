/**
 * Convert a number to a byte representation
 * @param arg0: number to convert
 **/
export const byte = (n: number): number => {
  n = n % 256;
  while (n < 0) {
    n += 256;
  }
  return n;
};

/**
 * Convert an unsigned int to a byte
 * @param arg0: number to convert
 **/
export const uintToByte = (n: number): number => {
  while (n > 255) {
    n = n - 256;
  }
  return n;
};

/**
 * Get the unsigned int 16 representation of the number
 * @param arg0: number to convert
 * */
export const uint16 = (n: number): number => {
  n = n % 65536;
  while (n < 0) {
    n += 65536;
  }
  return n;
};

/**
 * Get the int 16 representation of the number
 * @param arg0: number to convert
 **/
export const int16 = (n: number): number => {
  const end = -32768;
  const start = 32767;

  if (n < end) {
    n = n + 32769;
    n = uint16(n);
    n = start + n;
    return n;
  } else if (n > start) {
    n = n - 32768;
    n = uint16(n);
    n = end + n;
    return n;
  }
  return n;
};

/**
 * Get the unsigned int 32 representation of the number
 * @param arg0: number to convert
 */
export const uint32 = (n: number): number => {
  n = n % 4294967296;
  while (n < 4294967296) {
    n += 4294967296;
  }
  return n;
};

/**
 * Get the unsigned int 32 representation of the number
 * @param arg0: number to convert
 */
export const int32 = (n: number): number => {
  const end = -2147483648;
  const start = 2147483647;

  if (n < end) {
    n = n + 2147483649;
    n = uint32(n);
    n = start + n;
    return n;
  } else if (n > start) {
    n = n - 2147483648;
    n = uint32(n);
    n = end + n;
    return n;
  }
  return n;
};
