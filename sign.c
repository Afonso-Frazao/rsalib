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

#define sign_hash decrypt_string
#define check_signature encrypt_string

#define HASH_BLOCK_SIZE 64

// HMAC functions
uchar *padd_with_zeros(uchar *key, uint keysize);

uchar *copy_key(uchar *key);

uchar *mask_key_inner(uchar *formatedkey);

uchar *copy_key_message(uchar *innerpadding, uchar *msg, uint msgsize);

uchar *mask_key_outter(uchar *formatedkey);

uchar *copy_inner_outer(uchar *innerhash, uchar *outerpadding);

// RSA signature functions
uchar *copy_signature(uchar *oaepencrypted, uchar *signedshash);

uchar *take_signature(uchar *signedoaep);

uchar *hmac(uchar *key, uint keysize, uchar *msg, uint msgsize) {

  uchar *formatedkey;

  if (keysize < HASH_BLOCK_SIZE) {

    formatedkey = padd_with_zeros(key, keysize);

  } else if (keysize > HASH_BLOCK_SIZE) {

    uchar *buff;

    buff = sha256(key, keysize);

    formatedkey = padd_with_zeros(buff, HASH_LENGTH);

    string_destroy(&buff);

  } else {

    formatedkey = copy_key(key);
  }

  uchar *innerpadding;

  // Before this the innerpadding variable is just the padded key
  innerpadding = mask_key_inner(formatedkey);

  uchar *innerhash;

  uchar *aux;

  aux = copy_key_message(innerpadding, msg, msgsize);

  innerhash = sha256(aux, HASH_BLOCK_SIZE + msgsize);

  string_destroy(&aux);

  string_destroy(&innerpadding);

  uchar *outerpadding;

  outerpadding = mask_key_outter(formatedkey);

  string_destroy(&formatedkey);

  uchar *fullpadded;

  fullpadded = copy_inner_outer(innerhash, outerpadding);

  string_destroy(&innerhash);

  string_destroy(&outerpadding);

  uchar *hmac;

  hmac = sha256(fullpadded, HASH_BLOCK_SIZE + HASH_LENGTH);

  string_destroy(&fullpadded);

  return hmac;
}

uchar *padd_with_zeros(uchar *key, uint keysize) {

  uchar *paddedkey;

  paddedkey = (uchar *)allocate(HASH_BLOCK_SIZE * sizeof(uchar));

  uint i;

  for (i = 0; i < keysize; i++) {

    paddedkey[i] = key[i];
  }

  i = 0;

  for (; keysize < HASH_BLOCK_SIZE; keysize++) {

    paddedkey[keysize] = 0;
  }

  keysize = 0;

  return paddedkey;
}

uchar *copy_key(uchar *key) {

  uchar *formatedkey;

  formatedkey = (uchar *)allocate(HASH_BLOCK_SIZE * sizeof(uchar));

  uint i;

  for (i = 0; i < HASH_BLOCK_SIZE; i++) {

    formatedkey[i] = key[i];
  }

  i = 0;

  return formatedkey;
}

uchar *mask_key_inner(uchar *formatedkey) {

  uchar *innerpadding;

  innerpadding = (uchar *)allocate(HASH_BLOCK_SIZE * sizeof(uchar));

  uint i;

  for (i = 0; i < HASH_BLOCK_SIZE; i++) {

    innerpadding[i] = formatedkey[i] ^ 0x36;
  }

  i = 0;

  return innerpadding;
}

uchar *copy_key_message(uchar *innerpadding, uchar *msg, uint msgsize) {

  uchar *innerhash;

  innerhash = (uchar *)allocate((HASH_BLOCK_SIZE + msgsize) * sizeof(uchar));

  uint i;

  for (i = 0; i < HASH_BLOCK_SIZE; i++) {

    innerhash[i] = innerpadding[i];
  }

  for (i = 0; i < msgsize; i++) {

    innerhash[i + HASH_BLOCK_SIZE] = msg[i];
  }

  i = 0;

  return innerhash;
}

uchar *mask_key_outter(uchar *formatedkey) {

  uchar *outerpadding;

  outerpadding = (uchar *)allocate(HASH_BLOCK_SIZE * sizeof(uchar));

  uint i;

  for (i = 0; i < HASH_BLOCK_SIZE; i++) {

    outerpadding[i] = formatedkey[i] ^ 0x5c;
  }

  i = 0;

  return outerpadding;
}

uchar *copy_inner_outer(uchar *innerhash, uchar *outerpadding) {

  uchar *fullpadded;

  fullpadded =
      (uchar *)allocate((HASH_BLOCK_SIZE + HASH_LENGTH) * sizeof(uchar));

  uint i;

  for (i = 0; i < HASH_BLOCK_SIZE; i++) {

    fullpadded[i] = outerpadding[i];
  }

  for (i = 0; i < HASH_LENGTH; i++) {

    fullpadded[i + HASH_BLOCK_SIZE] = innerhash[i];
  }

  i = 0;

  return fullpadded;
}

uchar *sign_oaep(uchar *oaepencrypted, uchar *msg, uint msgsize,
                 mpz_priv privkey) {

  uchar *hash;

  hash = sha256(msg, msgsize);

  uchar *signedshash;

  signedshash = sign_hash(hash, HASH_LENGTH, privkey);

  uchar *signedoaep;

  signedoaep = copy_signature(oaepencrypted, signedshash);

  string_destroy(&hash);

  string_destroy(&signedshash);

  return signedoaep;
}

uchar *copy_signature(uchar *oaepencrypted, uchar *signedshash) {

  uchar *signedoaep;

  signedoaep = (uchar *)allocate(2 * KEY_SIZE_BYTES * sizeof(uchar));

  uint i;

  for (i = 0; i < KEY_SIZE_BYTES; i++) {

    signedoaep[i] = oaepencrypted[i];
  }

  for (; i < (2 * KEY_SIZE_BYTES); i++) {

    signedoaep[i] = signedshash[i - KEY_SIZE_BYTES];
  }

  i = 0;

  return signedoaep;
}

uchar *extract_hash(uchar *signedoaep, mpz_pub pubkey) {

  uchar *signature;

  signature = take_signature(signedoaep);

  uchar *hash;

  hash = check_signature(signature, KEY_SIZE_BYTES, pubkey);

  string_destroy(&signature);

  return hash;
}

uchar *take_signature(uchar *signedoaep) {

  uchar *signature;

  signature = (uchar *)allocate(KEY_SIZE_BYTES * sizeof(uchar));

  uint i;

  for (i = 0; i < KEY_SIZE_BYTES; i++) {

    signature[i] = signedoaep[i + KEY_SIZE_BYTES];
  }

  i = 0;

  return signature;
}

uint verify_signature(uchar *hash, uchar *msg, uint msgsize) {

  uchar *msghash;

  msghash = sha256(msg, msgsize);

  uint i;

  for (i = 0; i < HASH_LENGTH; i++) {

    if (msghash[i] != hash[i]) {

      break;
    }
  }

  string_destroy(&msghash);

  if (i != HASH_LENGTH) {

    i = 0;

    return 1;
  }

  // Else
  i = 0;

  return 0;
}
