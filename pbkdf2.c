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

uchar *generate_block(uchar *password, uint paswordsize, uchar *salt,
                      uint saltsize, uint itnum, uint count);

void concatenate_block(uchar *derivedkey, uchar *currentblock, uint blocknum,
                       uint sizetocat);

uchar *copy_salt_count(uchar *salt, uint saltsize, uint count);

// For 2048 bit RSA seed generation the recommended parameters are:
//
// 16+ character password with capitals, numbers and symbols;
// 64 byte randomlly generated salt (recommend using /dev/random)
// 600.000 iteractions
// 256 byte derived key

uchar *pbkdf2(uchar *password, uint paswordsize, uchar *salt, uint saltsize,
              uint itnum, uint derivedkeysize) {

  uint blocknum;
  uint finalblocksize;

  // The same as ceil(derivedkeysize / HASH_LENGTH)
  blocknum = (derivedkeysize + HASH_LENGTH - 1) / HASH_LENGTH;
  finalblocksize = derivedkeysize % HASH_LENGTH;
  if (finalblocksize == 0) {

    finalblocksize = HASH_LENGTH;
  }

  uchar *currentblock;

  uchar *derivedkey;

  derivedkey = (uchar *)allocate(derivedkeysize * sizeof(uchar));

  uint i;

  for (i = 1; i <= blocknum; i++) {

    currentblock =
        generate_block(password, paswordsize, salt, saltsize, itnum, i);

    if (i != blocknum) {

      concatenate_block(derivedkey, currentblock, i - 1, HASH_LENGTH);

    } else {

      concatenate_block(derivedkey, currentblock, i - 1, finalblocksize);
    }

    string_destroy(&currentblock);
  }

  i = 0;

  blocknum = 0;

  return derivedkey;
}

uchar *generate_block(uchar *password, uint paswordsize, uchar *salt,
                      uint saltsize, uint itnum, uint count) {

  uchar *hmactext;

  hmactext = copy_salt_count(salt, saltsize, count);

  uchar *currentblock;

  currentblock = hmac(password, paswordsize, hmactext, saltsize + sizeof(int));

  uchar *aux1, *aux2;

  aux2 = (uchar *)allocate(HASH_LENGTH * sizeof(uchar));

  copy_str(aux2, currentblock, HASH_LENGTH);

  uint i;
  uint j;

  for (i = 1; i < itnum; i++) {

    aux1 = hmac(password, paswordsize, aux2, HASH_LENGTH);

    string_destroy(&aux2);

    for (j = 0; j < HASH_LENGTH; j++) {

      currentblock[j] ^= aux1[j];
    }

    aux2 = aux1;
  }

  string_destroy(&aux1);
  aux2 = NULL;

  i = 0;

  string_destroy(&hmactext);

  return currentblock;
}

void concatenate_block(uchar *derivedkey, uchar *currentblock, uint blocknum,
                       uint sizetocat) {

  uint i;

  for (i = 0; i < sizetocat; i++) {

    derivedkey[i + (blocknum * HASH_LENGTH)] = currentblock[i];
  }

  i = 0;

  return;
}

uchar *copy_salt_count(uchar *salt, uint saltsize, uint count) {

  uchar *hmactext;

  hmactext = (uchar *)allocate((saltsize + sizeof(uint)) * sizeof(uchar));

  uint i;

  for (i = 0; i < saltsize; i++) {

    hmactext[i] = salt[i];
  }

  int_little_to_big_endian((uchar *)&count);

  uchar *aux;

  aux = (uchar *)&count;

  for (i = 0; i < sizeof(int); i++) {

    hmactext[i + saltsize] = aux[i];
  }

  aux = NULL;

  i = 0;

  return hmactext;
}
