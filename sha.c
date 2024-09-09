/*
 * Copyright (C) 2024 Afonso Frazão
 *
 * This file is part of the rsalib C Library.
 *
 * The rsalib C Library is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The rsalib C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the Cryptographic C Library. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "rsalib.h"

#include <stdint.h>

// Define to 0 if the machine is big endian based
#define LITTLE_END 1

// Define to 1 if you're working with a 32 bit machine
#define PC_32_BIT 0

ulong calculate_str_size(uchar *str);

ulong calculate_padded_size(ulong size);

void copy_str(uchar *target, uchar *str, uint strsize);

void pad(uchar *padded, ulong size, ulong paddedsize);

void long_little_to_big_endian(uchar *big_endian);

void padded_little_to_big_endian(uchar *padded, ulong paddedsize);

void process_schedule(uint *schedule, uint *padded, uint block);

void compress(uint *schedule, uint *hashvalues, uint *roundconstants);

uint csr(uint num, uint shift);

uchar *convert_hash(uint *hashvalues);

void clear_constants(uint *hashvalues, uint *roundconstants);

// Send the address of a NULL terminated string
uchar *sha256(uchar *str, uint strsize) {

  uint hashvalues[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  uint roundconstants[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  // ulong strsize;
  ulong paddedsize;

  // strsize = 0;
  paddedsize = 0;

  // strsize = calculate_str_size(str);

  paddedsize = calculate_padded_size(strsize);

  uchar *padded;

  padded = (uchar *)allocate(paddedsize * sizeof(uchar));

  copy_str(padded, str, strsize);

  pad(padded, strsize, paddedsize);

  strsize = 0;

  // string_destroy((uchar **)str);

  padded_little_to_big_endian(padded, paddedsize);

  uint *schedule;

  schedule = (uint *)allocate(64 * sizeof(uint));

  uint block;
  uint blocknum;

  blocknum = paddedsize / 64;

  paddedsize = 0;

  for (block = 0; block < blocknum; block++) {

    process_schedule(schedule, (uint *)padded, block);

    compress(schedule, hashvalues, roundconstants);
  }

  block = 0;
  blocknum = 0;

  string_destroy((uchar **)&schedule);

  string_destroy(&padded);

  uchar *hash;

  hash = convert_hash(hashvalues);

  // hash[32] = '\0';

  clear_constants(hashvalues, roundconstants);

  // The returned string is always 32 bytes long plus one byte for the string
  // terminator
  return hash;
}

ulong calculate_str_size(uchar *str) {

  ulong size;

  for (size = 0; str[size] != '\0'; size++)
    ;

  return size;
}

ulong calculate_padded_size(ulong size) {

  ulong rem;
  ulong div;

  rem = 0;
  div = 0;

  rem = size % 64;
  div = size / 64;

  if (rem >= 55) {

    rem = 0;

    // If this condition is true there is no space for the 1 bit plus the 64 bit
    // integer
    return ((div + 2) * 64);

  } else {

    rem = 0;

    return ((div + 1) * 64);
  }
}

void copy_str(uchar *target, uchar *str, uint strsize) {

  uint i;

  for (i = 0; i < strsize; i++) {

    target[i] = str[i];
  }

  i = 0;

  return;
}

void pad(uchar *padded, ulong strsize, ulong paddedsize) {

  // 1 bit followed by zeroes
  padded[strsize] = 128;

  uint i;

  i = 0;

  for (i = strsize + 1; i < paddedsize - 8; i++) {

    padded[i] = 0;
  }

  // Size in bits not bytes;
  strsize *= 8;

  if (LITTLE_END) {

    // Size is in little endian format
    long_little_to_big_endian((uchar *)&strsize);
  }

  uchar *sizeptr;

  sizeptr = (uchar *)&strsize;

  for (i = 0; i < 8; i++) {

    padded[paddedsize - 8 + i] = sizeptr[i];
  }

  i = 0;

  sizeptr = NULL;

  return;
}

// This function is meant for 64 bit integers
void long_little_to_big_endian(uchar *big_endian) {

  uint i;

  uchar aux;

  aux = 0;

  if (PC_32_BIT) {

    for (i = 0; i < 2; i++) {

      aux = big_endian[i];
      big_endian[i] = big_endian[3 - i];
      big_endian[3 - i] = aux;
    }
  } else {

    for (i = 0; i < 4; i++) {

      aux = big_endian[i];
      big_endian[i] = big_endian[7 - i];
      big_endian[7 - i] = aux;
    }
  }

  i = 0;

  aux = 0;

  return;
}

void padded_little_to_big_endian(uchar *padded, ulong paddedsize) {

  uint i;
  uint j;

  uchar aux;

  aux = 0;

  for (i = 0; i < paddedsize; i += 4) {

    for (j = 0; j < 2; j++) {

      aux = padded[i + j];
      padded[i + j] = padded[i + 3 - j];
      padded[i + 3 - j] = aux;
    }
  }

  i = 0;
  j = 0;

  aux = 0;

  return;
}

void process_schedule(uint *schedule, uint *padded, uint block) {

  uint i;

  for (i = 0; i < 16; i++) {

    schedule[i] = padded[(block * 16) + i];
  }

  uint s0;
  uint s1;

  s0 = 0;
  s1 = 0;

  for (i = 16; i < 64; i++) {

    s0 = csr(schedule[i - 15], 7) ^ csr(schedule[i - 15], 18) ^
         (schedule[i - 15] >> 3);

    s1 = csr(schedule[i - 2], 17) ^ csr(schedule[i - 2], 19) ^
         (schedule[i - 2] >> 10);

    schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
  }

  s0 = 0;
  s1 = 0;

  i = 0;

  return;
}

void compress(uint *schedule, uint *hashvalues, uint *roundconstants) {

  uint a = hashvalues[0];
  uint b = hashvalues[1];
  uint c = hashvalues[2];
  uint d = hashvalues[3];
  uint e = hashvalues[4];
  uint f = hashvalues[5];
  uint g = hashvalues[6];
  uint h = hashvalues[7];

  uint i;
  uint temp1, temp2;
  uint s0, s1;
  uint ch, maj;

  temp1 = 0;
  temp2 = 0;
  s0 = 0;
  s1 = 0;
  ch = 0;
  maj = 0;

  for (i = 0; i < 64; i++) {

    s1 = csr(e, 6) ^ csr(e, 11) ^ csr(e, 25);
    ch = (e & f) ^ ((~e) & g);
    temp1 = h + s1 + ch + roundconstants[i] + schedule[i];

    s0 = csr(a, 2) ^ csr(a, 13) ^ csr(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  i = 0;
  temp1 = 0;
  temp2 = 0;
  s0 = 0;
  s1 = 0;
  ch = 0;
  maj = 0;

  hashvalues[0] += a;
  hashvalues[1] += b;
  hashvalues[2] += c;
  hashvalues[3] += d;
  hashvalues[4] += e;
  hashvalues[5] += f;
  hashvalues[6] += g;
  hashvalues[7] += h;

  a = 0;
  b = 0;
  c = 0;
  d = 0;
  e = 0;
  f = 0;
  g = 0;
  h = 0;

  return;
}

// Circular shift right
/*uint csr(uint num, uint shift) {

  uint left;
  uint right;

  shift %= 32;

  left = num << (32 - shift);
  right = num >> shift;

  num = left | right;

  left = 0;
  right = 0;

  return num;
}*/

// Circular shift right
/*uint csr(uint num, uint shift) {

  uint result;

  asm("rorl %1, %0" : "=r"(result) : "c"(shift), "0"(num));

  return result;
}*/

uint csr(uint num, uint shift) {

  return (num >> shift) | (num << (32 - shift));
}

uchar *convert_hash(uint *hashvalues) {

  uint *hash;

  hash = (uint *)allocate(8 * sizeof(uint));

  uint i;

  for (i = 0; i < 8; i++) {

    // hash[i] = hashvalues[7 - i];
    hash[i] = hashvalues[i];

    if (LITTLE_END) {

      int_little_to_big_endian((uchar *)&(hash[i]));
    }
  }

  i = 0;

  return (uchar *)hash;
}

void int_little_to_big_endian(uchar *num) {

  uint i;
  uchar aux;

  for (i = 0; i < 2; i++) {

    aux = num[i];
    num[i] = num[3 - i];
    num[3 - i] = aux;
  }

  i = 0;

  return;
}

void clear_constants(uint *hashvalues, uint *roundconstants) {

  uint i;

  for (i = 0; i < 8; i++) {

    hashvalues[i] = 0;
  }

  for (i = 0; i < 64; i++) {

    roundconstants[i] = 0;
  }

  i = 0;

  return;
}
