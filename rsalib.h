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
 * along with the rsalib C Library. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#ifndef HEAD_H
#define HEAD_H

#include <stdio.h>
#include <stdlib.h>

#include <gmp.h>

#define KEY_SIZE_BYTES 256

#define HASH_LENGTH 32

/*typedef volatile void vvoid;
typedef volatile char vchar;
typedef volatile int vint;
typedef volatile long vlong;

typedef volatile unsigned char vuchar;
typedef volatile unsigned int vuint;
typedef volatile unsigned long vulong;*/

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;

typedef struct _mpz_pub {

  mpz_t e;
  mpz_t n;

} mpz_pub;

typedef struct _mpz_priv {

  // mpz_t d;
  mpz_t p;
  mpz_t q;
  mpz_t dp;
  mpz_t dq;
  mpz_t qinv;

  mpz_t n;

} mpz_priv;

typedef struct _mpz_keys {

  mpz_t e;

  // mpz_t d;
  mpz_t p;
  mpz_t q;
  mpz_t dp;
  mpz_t dq;
  mpz_t qinv;

  mpz_t n;

} mpz_keys;

mpz_keys generate_keys(uchar *password, uint passwordsize, uchar *saltfile);

void password_protected_seed(mpz_t seed, uchar *password, uint passwordsize,
                             uchar *saltfile);

uchar *get_salt(uchar *saltfile, uint *saltsize);

uchar *write_pub_key(mpz_pub pubkey);

mpz_pub get_pub_key(char *pubstring);

void separate_keys(mpz_keys keypair, mpz_pub *pubkey, mpz_priv *privkey);

void keypair_destroy(uchar ***keypair);

uchar *encrypt_string(uchar *str, uint strlength, mpz_pub pubkey);

uchar *decrypt_string(uchar *str, uint strlength, mpz_priv privkey);

void *allocate(uint size);

void string_destroy(uchar **key);

uchar *sha256(uchar *str, uint size);

void copy_str(uchar *target, uchar *str, uint strsize);

void int_little_to_big_endian(uchar *num);

uchar *oaep_encode(uchar *msg, uchar *label, uint labelsize);

uchar *oaep_decode(uchar *encoded, uchar *label, uint labelsize);

uchar *mgf1(uchar *seed, uint seedsize, uint masksize);

uint string_length(uchar *str);

uchar *hmac(uchar *key, uint keysize, uchar *msg, uint msgsize);

uchar *sign_oaep(uchar *oaepencrypted, uchar *msg, uint msgsize,
                 mpz_priv privkey);

uchar *extract_hash(uchar *signedoaep, mpz_pub pubkey);

uchar *generate_seed_string(uint size);

uint verify_signature(uchar *hash, uchar *msg, uint msgsize);

uchar *pbkdf2(uchar *password, uint paswordsize, uchar *salt, uint saltsize,
              uint itnum, uint size);

#endif
