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

#include "rsalib.h"

#define MASKEDDB_LENGTH (KEY_SIZE_BYTES - HASH_LENGTH - 1)

// #define KEY_SIZE_BYTES 512

uchar *copy_label(uchar *hashedlabel);

void padd_encoded(uchar *encoded, uint msglen);

void copy_message(uchar *encoded, uchar *msg, uint msglen);

void copy_masked_seed(uchar *encoded, uchar *seed);

uchar *copy_mask_seed(uchar *seed, uint seedsize);

void copy_counter(uchar *str, uchar *counter, uint seedsize);

void copy_hash(uchar *mask, uchar *hash, uint counter, uint masksize);

uchar *take_maskedDB(uchar *encoded);

uchar *take_maskedseed(uchar *encoded);

uchar *verifypadding(uchar *maskedDB, uchar *dbmask, uchar *label,
                     uint labelsize);

// The max size for the message (msg) in bytes (including the '\0' at the end)
// is KEY_SIZE - (2 * HASH_LENGTH) - 2

// The mask seed size must be the same as HASH_LENGTH
uchar *oaep_encode(uchar *msg, uchar *label, uint labelsize) {

  uchar *lhash;

  lhash = sha256(label, labelsize);

  uchar *encoded;

  encoded = copy_label(lhash);

  string_destroy(&lhash);

  uint msglen;

  msglen = string_length(msg);

  padd_encoded(encoded, msglen);

  copy_message(encoded, msg, msglen);

  msglen = 0;

  uchar *seed;

  seed = generate_seed_string(HASH_LENGTH);

  uchar *dbmask;

  dbmask = mgf1(seed, HASH_LENGTH, MASKEDDB_LENGTH);

  uint i;

  // Create the maskedDB
  for (i = 0; i < MASKEDDB_LENGTH; i++) {

    encoded[i] ^= dbmask[i];
  }

  string_destroy(&dbmask);

  i = 0;

  uchar *seedmask;

  // seedmask = mgf1(dbmask, MASKEDDB_LENGTH, HASH_LENGTH);
  seedmask = mgf1(encoded, MASKEDDB_LENGTH, HASH_LENGTH);

  for (i = 0; i < HASH_LENGTH; i++) {

    seed[i] ^= seedmask[i];
  }

  i = 0;

  string_destroy(&seedmask);

  copy_masked_seed(encoded, seed);

  string_destroy(&seed);

  return encoded;
}

uchar *oaep_decode(uchar *encoded, uchar *label, uint labelsize) {

  uchar *maskedDB;

  maskedDB = take_maskedDB(encoded);

  uchar *seedmask;

  seedmask = mgf1(maskedDB, MASKEDDB_LENGTH, HASH_LENGTH);

  uchar *maskedseed;

  maskedseed = take_maskedseed(encoded);

  uchar *seed;

  seed = (uchar *)allocate(HASH_LENGTH * sizeof(uchar));

  uint i;

  for (i = 0; i < HASH_LENGTH; i++) {

    seed[i] = maskedseed[i] ^ seedmask[i];
  }

  i = 0;

  string_destroy(&maskedseed);
  string_destroy(&seedmask);

  uchar *dbmask;

  dbmask = mgf1(seed, HASH_LENGTH, MASKEDDB_LENGTH);

  string_destroy(&seed);

  uchar *msg;

  msg = verifypadding(maskedDB, dbmask, label, labelsize);

  string_destroy(&maskedDB);
  string_destroy(&dbmask);

  return msg;
}

// The recommended seed size is 256
uchar *mgf1(uchar *seed, uint seedsize, uint masksize) {

  uchar *mask;

  mask = (uchar *)allocate(masksize * sizeof(uchar));

  uchar *hash;

  uchar *str;

  str = copy_mask_seed(seed, seedsize);

  uint counter;
  uint count;

  count = (masksize + HASH_LENGTH - 1) / HASH_LENGTH;

  for (counter = 0; counter < count; counter++) {

    copy_counter(str, (uchar *)&counter, seedsize);

    hash = sha256(str, seedsize + 4);

    copy_hash(mask, hash, counter, masksize);

    string_destroy(&hash);
  }

  counter = 0;

  string_destroy(&str);

  return mask;
}

uchar *copy_label(uchar *hashedlabel) {

  uchar *encoded;

  encoded = (uchar *)allocate(KEY_SIZE_BYTES * sizeof(uchar));

  encoded[KEY_SIZE_BYTES - 1] = 0;

  uint i;

  for (i = 0; i < HASH_LENGTH; i++) {

    encoded[i + (KEY_SIZE_BYTES - (2 * HASH_LENGTH) - 1)] = hashedlabel[i];
  }

  i = 0;

  return encoded;
}

uint string_length(uchar *str) {

  uint size;

  for (size = 0; str[size] != '\0'; size++)
    ;

  return size;
}

void padd_encoded(uchar *encoded, uint msglen) {

  uint i;

  encoded[msglen] = 1;

  for (i = msglen + 1; i < (KEY_SIZE_BYTES - (2 * HASH_LENGTH) - 1); i++) {

    encoded[i] = 0;
  }

  i = 0;

  return;
}

void copy_message(uchar *encoded, uchar *msg, uint msglen) {

  uint i;

  for (i = 0; i < msglen; i++) {

    encoded[i] = msg[i];
  }

  i = 0;

  return;
}

uchar *generate_seed_string(uint size) {

  uchar *seed;

  seed = (uchar *)allocate(size * sizeof(uchar));

  FILE *fp;

  fp = NULL;

  fp = fopen("/dev/random", "rb");

  fread((char *)seed, sizeof(*seed), size, fp);

  fclose(fp);

  fp = NULL;

  size = 0;

  return seed;
}

void copy_masked_seed(uchar *encoded, uchar *seed) {

  uint i;

  for (i = 0; i < HASH_LENGTH; i++) {

    encoded[i + (MASKEDDB_LENGTH)] = seed[i];
  }

  i = 0;

  return;
}

uchar *copy_mask_seed(uchar *seed, uint seedsize) {

  uchar *str;

  str = (uchar *)allocate((seedsize * sizeof(uchar)) + sizeof(uint));

  uint i;

  for (i = 0; i < seedsize; i++) {

    str[i] = seed[i];
  }

  i = 0;

  return str;
}

void copy_counter(uchar *str, uchar *counter, uint seedsize) {

  uint i;

  for (i = 0; i < 4; i++) {

    str[seedsize + i] = counter[3 - i];
  }

  i = 0;

  return;
}

void copy_hash(uchar *mask, uchar *hash, uint counter, uint masksize) {

  uint i;

  for (i = 0; (i < HASH_LENGTH) && ((i + (counter * HASH_LENGTH)) < masksize);
       i++) {

    mask[i + (counter * HASH_LENGTH)] = hash[i];
  }

  i = 0;

  return;
}

uchar *take_maskedDB(uchar *encoded) {

  uchar *maskedDB;

  maskedDB = (uchar *)allocate((MASKEDDB_LENGTH) * sizeof(uchar));

  uint i;

  for (i = 0; i < (MASKEDDB_LENGTH); i++) {

    maskedDB[i] = encoded[i];
  }

  i = 0;

  return maskedDB;
}

uchar *take_maskedseed(uchar *encoded) {

  uchar *maskedseed;

  maskedseed = (uchar *)allocate(HASH_LENGTH * sizeof(uchar));

  uint i;

  for (i = 0; i < HASH_LENGTH; i++) {

    maskedseed[i] = encoded[i + (MASKEDDB_LENGTH)];
  }

  i = 0;

  return maskedseed;
}

uchar *verifypadding(uchar *maskedDB, uchar *dbmask, uchar *label,
                     uint labelsize) {

  uchar *msg;

  msg = (uchar *)allocate((MASKEDDB_LENGTH - HASH_LENGTH) * sizeof(uchar));

  uint i;

  for (i = 0; i < (MASKEDDB_LENGTH - HASH_LENGTH); i++) {

    msg[i] = maskedDB[i] ^ dbmask[i];

    if (msg[i] == 1) {

      msg[i] = '\0';

      break;
    }
  }

  if (i == (MASKEDDB_LENGTH - HASH_LENGTH)) {

    i = 0;
    string_destroy(&msg);

    return NULL;
  }

  for (i++; i < (MASKEDDB_LENGTH - HASH_LENGTH); i++) {

    if ((maskedDB[i] ^ dbmask[i]) != 0) {

      i = 0;
      string_destroy(&msg);

      return NULL;
    }
  }

  uchar *lhash;

  lhash = sha256(label, labelsize);

  for (; i < MASKEDDB_LENGTH; i++) {

    if ((maskedDB[i] ^ dbmask[i]) !=
        lhash[i - (MASKEDDB_LENGTH - HASH_LENGTH)]) {

      i = 0;
      string_destroy(&msg);
      string_destroy(&lhash);

      return NULL;
    }
  }

  string_destroy(&lhash);

  i = 0;

  return msg;
}
