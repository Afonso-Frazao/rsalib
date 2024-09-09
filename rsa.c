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

#include <stdio.h>

// size of the 'n' of the key in bits
#define KEY_SIZE 2048

// Should be equal or bigger than the key size in bytes
#define PRIME_SEED_SIZE 256
#define SALT_SIZE 64
#define PBKDF2_ITERATIONS 600000

#define E_TRIES 64
#define PRIME_NUMBER_CHECKS 256 // MAX 1229
#define MILLER_RABIN_ITERATIONS 128

// each unencrypted block will be ((KEY_SIZE / 8) - 1) bytes long the encrypted
// blocks will be (KEY_SIZE / 8) bytes long
#define BLOCK_SIZE 255

/*
#define KEY_SIZE 4096
#define PRIME_SEED_SIZE 512
#define E_TRIES 128
#define PRIME_NUMBER_CHECKS 512 // MAX 1229
#define MILLER_RABIN_ITERATIONS 256
#define BLOCK_SIZE 511
*/

void generate_seed(mpz_t seed);

void generate_state(gmp_randstate_t state, mpz_t seed);

void generate_random_candidate(mpz_t num, gmp_randstate_t state);

void gen_primes(mpz_t p, mpz_t q, uchar *password, uint passwordsize,
                uchar *saltfile);

void primes_loop(mpz_t num, mpz_t seed);

uint check_primes(mpz_t num);

uint miller_rabin(mpz_t num);

void miller_rabin_cleanup(gmp_randstate_t state, mpz_t a, mpz_t x, mpz_t y,
                          mpz_t two, mpz_t num_1, uint *i, mpz_t j, mpz_t s,
                          mpz_t d);

void calculate_n(mpz_t n, mpz_t p, mpz_t q);

void totient(mpz_t t, mpz_t p, mpz_t q);

uint calculate_e(mpz_t e, mpz_t t);

void mmi(mpz_t d, mpz_t e, mpz_t t);

void calculate_crt_coefficients(mpz_t dp, mpz_t dq, mpz_t qinv, mpz_t p,
                                mpz_t q, mpz_t d);

// uchar **write_key(mpz_t n, mpz_t e, mpz_t d);

// Encryption functions
void encrypt_file(uchar **filename, mpz_pub pubkey);

void encrypt(mpz_t num, mpz_pub pubkey);

uchar *calculate_efoutname(uchar **filename);

// Decryption functions
void decrypt_file(uchar **filename, mpz_priv privkey);

void decrypt(mpz_t num, mpz_priv privkey);

uchar *calculate_dfoutname(uchar **filename);

uint verify_string(uchar *str);

void state_destroy(gmp_randstate_t state);

void mpz_destroy(mpz_t var);

// void structs_destroy(mpz_pub pubkey, mpz_priv privkey);

void mpz_keys_destroy(mpz_keys keypair);

void mpz_pub_destroy(mpz_pub pubkey);

void mpz_priv_destroy(mpz_priv privkey);

// TODO add error verification for the function calls
// TODO add const atribute were needed

/*int main() {

  uchar *pbk;

  pbk = pbkdf2((uchar *)"password", 8, (uchar *)"salt", 4, 600000, 32);

  for (int i = 0; i < 32; i++) {

    printf("%.2hhx", pbk[i]);
  }
  printf("\n\n");

  string_destroy((uchar **)&pbk);

  uchar *hmacstr;

  hmacstr = hmac((uchar *)"key", 3,
                 (uchar *)"The quick brown fox jumps over the lazy dog", 43);

  for (int i = 0; i < HASH_LENGTH; i++) {

    printf("%.2hhx", hmacstr[i]);
  }
  printf("\n\n");

  string_destroy((uchar **)&hmacstr);

  uchar *msg;
  uchar *label;
  uchar *encoded;
  uchar *decoded;

  msg = (uchar *)allocate(10 * sizeof(uchar));
  label = (uchar *)allocate(10 * sizeof(uchar));

  sprintf((char *)msg, "Hello");
  sprintf((char *)label, "Bye");

  printf("message: %s\n\n", msg);

  encoded = oaep_encode(msg, label, 3);

  decoded = oaep_decode(encoded, label, 3);

  if (decoded == NULL) {

    printf("wrong label or message\n\n");

  } else {

    printf("decoded message: %s\n\n", decoded);
  }

  string_destroy((uchar **)&msg);
  string_destroy((uchar **)&label);
  string_destroy((uchar **)&encoded);
  string_destroy((uchar **)&decoded);

  uchar *str;

  uchar *seed;

  seed = (uchar *)allocate(256 * sizeof(uchar));

  sprintf((char *)seed, "foo");

  str = mgf1(seed, 3, 3);

  for (uint i = 0; i < 3; i++) {
    printf("%.2hhx", str[i]);
  }
  printf("\n\n");

  string_destroy((uchar **)&str);
  string_destroy((uchar **)&seed);

  uchar *hello;

  hello = (uchar *)allocate(100 * sizeof(uchar));

  sprintf((char *)hello, "Hello, world!");

  uchar *bye;

  bye = sha256(hello, 13);

  for (uint i = 0; i < 32; i++) {
    printf("%.2hhx", bye[i]);
  }
  printf("\n\n");

  string_destroy((uchar **)&hello);
  string_destroy((uchar **)&bye);

  mpz_keys keypair;

  keypair = generate_keys(NULL, 0, NULL);

  mpz_pub pubkey;
  mpz_priv privkey;

  separate_keys(keypair, &pubkey, &privkey);

  mpz_keys_destroy(keypair);

  uchar *pubstring;

  pubstring = NULL;

  pubstring = write_pub_key(pubkey);

  string_destroy(&pubstring);

  uchar *hi;
  uchar *hiencrypted;
  uchar *hidecrypted;

  hi = (uchar *)allocate((BLOCK_SIZE + 1) * sizeof(uchar));

  sprintf((char *)hi, "Hello\n");

  printf("%s\n", hi);

  hiencrypted = encrypt_string(hi, 5, pubkey);

  printf("%s\n\n", hiencrypted);

  hidecrypted = decrypt_string(hiencrypted, KEY_SIZE_BYTES, privkey);

  printf("%s\n\n", hidecrypted);

  string_destroy(&hi);
  string_destroy(&hiencrypted);
  string_destroy(&hidecrypted);

  uchar *oaep;
  uchar *oaepencrypted;
  uchar *oaepsigned;
  uchar *hash;

  oaep = oaep_encode((uchar *)"String", (uchar *)"label", 5);

  oaepencrypted =
      (uchar *)encrypt_string((uchar *)oaep, KEY_SIZE_BYTES, pubkey);

  oaepsigned = sign_oaep(oaepencrypted, (uchar *)"String", 6, privkey);

  hash = extract_hash(oaepsigned, pubkey);

  if (verify_signature(hash, (uchar *)"String", 6) == 0) {

    printf("The signature matches the given key\n");

  } else {

    printf("The signature does not match\n");
  }

  string_destroy((uchar **)&oaep);
  string_destroy((uchar **)&oaepencrypted);
  string_destroy((uchar **)&oaepsigned);
  string_destroy((uchar **)&hash);

  mpz_pub_destroy(pubkey);
  mpz_priv_destroy(privkey);

  return 0;
}*/

// For randomlly generated key password = NULL
mpz_keys generate_keys(uchar *password, uint passwordsize, uchar *saltfile) {

  mpz_t p, q;

  mpz_init(p);
  mpz_init(q);

  mpz_t n;
  mpz_t t;
  mpz_t e;

  while (1) {

    gen_primes(p, q, password, passwordsize, saltfile);

    calculate_n(n, p, q);

    totient(t, p, q);

    if (calculate_e(e, t) == 0) {

      break;
    }

    mpz_destroy(n);
    mpz_destroy(t);
  }

  mpz_t d;

  mmi(d, e, t);

  mpz_destroy(t);

  mpz_t dp;
  mpz_t dq;
  mpz_t qinv;

  calculate_crt_coefficients(dp, dq, qinv, p, q, d);

  // d is not needed anymore
  mpz_destroy(d);

  mpz_keys keypair;

  mpz_init(keypair.e);
  mpz_init(keypair.p);
  mpz_init(keypair.q);
  mpz_init(keypair.dp);
  mpz_init(keypair.dq);
  mpz_init(keypair.qinv);
  mpz_init(keypair.n);

  mpz_set(keypair.e, e);
  mpz_set(keypair.p, p);
  mpz_set(keypair.q, q);
  mpz_set(keypair.dp, dp);
  mpz_set(keypair.dq, dq);
  mpz_set(keypair.qinv, qinv);
  mpz_set(keypair.n, n);

  mpz_destroy(p);
  mpz_destroy(q);

  mpz_destroy(e);
  mpz_destroy(n);

  mpz_destroy(dp);
  mpz_destroy(dq);
  mpz_destroy(qinv);

  return keypair;
}

void generate_seed(mpz_t seed) {

  FILE *fp;

  uchar *str;

  str = NULL;

  str = (uchar *)allocate(PRIME_SEED_SIZE * sizeof(uchar));

  // Can change to /dev/urandom
  fp = fopen("/dev/random", "rb");

  if (fp == NULL) {
    printf("Error opening /dev/random\n\n");
  }

  fread((char *)str, sizeof(*str), PRIME_SEED_SIZE, fp);

  // Add the string terminator
  // str[PRIME_SEED_SIZE] = '\0'; Already there I think

  fclose(fp);

  fp = NULL;

  mpz_init(seed);

  mpz_import(seed, PRIME_SEED_SIZE, 1, sizeof(*str), 0, 0, (char *)str);

  string_destroy(&(str));

  return;
}

void password_protected_seed(mpz_t seed, uchar *password, uint passwordsize,
                             uchar *saltfile) {

  uchar *salt;
  uint saltsize;

  salt = get_salt(saltfile, &saltsize);

  uchar *seedstr;

  seedstr = pbkdf2(password, passwordsize, salt, saltsize, PBKDF2_ITERATIONS,
                   PRIME_SEED_SIZE);

  string_destroy(&salt);

  saltsize = 0;

  mpz_import(seed, PRIME_SEED_SIZE, 1, sizeof(*seedstr), 0, 0, (char *)seedstr);

  string_destroy(&seedstr);

  return;
}

uchar *get_salt(uchar *saltfile, uint *saltsize) {

  FILE *fp;

  fp = fopen((char *)saltfile, "r");

  fscanf(fp, "%u ", saltsize);

  uchar *salt;

  salt = (uchar *)allocate(*saltsize * sizeof(uchar));

  fscanf(fp, "%s", (char *)salt);

  fclose(fp);

  fp = NULL;

  return salt;
}

void generate_salt_file(uchar *filename) {

  uchar *salt;

  salt = generate_seed_string(SALT_SIZE);

  FILE *fp;

  fp = fopen((char *)filename, "w");

  fprintf(fp, "%u %s", SALT_SIZE, salt);

  fclose(fp);

  fp = NULL;

  return;
}

void generate_state(gmp_randstate_t state, mpz_t seed) {

  gmp_randinit_mt(state);

  gmp_randseed(state, seed);

  return;
}

void generate_random_candidate(mpz_t num, gmp_randstate_t state) {

  mpz_urandomb(num, state, KEY_SIZE / 2);

  // Make the number bigger than 2 ^ ((KEY_SIZE / 2) - 1)
  mpz_setbit(num, (KEY_SIZE / 2) - 1);

  // Make the number odd
  mpz_setbit(num, 0);

  return;
}

void gen_primes(mpz_t p, mpz_t q, uchar *password, uint passwordsize,
                uchar *saltfile) {

  mpz_t(seed);

  if (password == NULL) {

    generate_seed(seed);

  } else {

    password_protected_seed(seed, password, passwordsize, saltfile);
  }

  primes_loop(p, seed);

  mpz_destroy(seed);

  if (password == NULL) {

    generate_seed(seed);
  }

  primes_loop(q, seed);

  mpz_destroy(seed);

  return;
}

void primes_loop(mpz_t num, mpz_t seed) {

  gmp_randstate_t state;

  generate_state(state, seed);

  while (1) {

    generate_random_candidate(num, state);

    if (check_primes(num) == 0 && miller_rabin(num) == 0) {

      // The number is prime
      break;
    }
  }

  state_destroy(state);

  return;
}

uint check_primes(mpz_t num) {

  FILE *fp;

  fp = fopen("primes.txt", "r");

  mpz_t prime;

  mpz_init(prime);

  mpz_t aux;

  mpz_init(aux);

  uint i;

  for (i = 0; i < PRIME_NUMBER_CHECKS; i++) {

    gmp_fscanf(fp, "%Zd ", &prime);

    mpz_mod(aux, num, prime);

    if (!(mpz_cmp_ui(aux, 0))) {

      break;
    }
  }

  mpz_destroy(aux);

  mpz_destroy(prime);

  fclose(fp);

  fp = NULL;

  if (i == PRIME_NUMBER_CHECKS) {

    i = 0;

    return (0);
  }

  // Else
  i = 0;

  return (1);
}

uint miller_rabin(mpz_t num) {

  mpz_t s;
  mpz_t d;
  mpz_t aux;

  mpz_init(s);
  mpz_init(d);
  mpz_init(aux);

  // d = num - 1
  mpz_sub_ui(d, num, 1);

  while (1) {

    if (mpz_tstbit(d, 0) == 1) {
      break;
    }

    mpz_div_ui(d, d, 2);

    mpz_add_ui(s, s, 1);
  }

  mpz_destroy(aux);

  gmp_randstate_t state;

  gmp_randinit_default(state);

  mpz_t seed;

  generate_seed(seed);

  gmp_randseed(state, seed);

  mpz_destroy(seed);

  // Make the number odd
  mpz_setbit(num, 0);

  uint i;

  mpz_t j;

  mpz_init(j);

  mpz_t a;
  mpz_t x;
  mpz_t y;
  mpz_t two;
  mpz_t num_1; // num - 1

  mpz_init(a);
  mpz_init(x);
  mpz_init(y);
  mpz_init(two);
  mpz_init(num_1);

  mpz_set_ui(two, 2);
  mpz_sub_ui(num_1, num, 1);

  for (i = 0; i < MILLER_RABIN_ITERATIONS; i++) {

    // The probabilitty of num being '0', '1' or 'num - 1' is so low
    // that I will ignore those cases
    mpz_urandomm(a, state, num);

    // This is a thing: https://en.wikipedia.org/wiki/Side-channel_attack
    mpz_powm_sec(x, a, d, num);

    for (mpz_set_ui(j, 0); mpz_cmp(j, s); mpz_add_ui(j, j, 1)) {

      mpz_powm_sec(y, x, two, num);

      if ((!(mpz_cmp_ui(y, 1))) && mpz_cmp_ui(x, 1) && mpz_cmp(x, num_1)) {

        miller_rabin_cleanup(state, a, x, y, two, num_1, &i, j, s, d);

        // Not prime
        return (1);
      }

      mpz_set(x, y);
    }

    if (mpz_cmp_ui(y, 1)) {

      miller_rabin_cleanup(state, a, x, y, two, num_1, &i, j, s, d);

      return (1);
    }
  }

  miller_rabin_cleanup(state, a, x, y, two, num_1, &i, j, s, d);

  // Probably prime
  return (0);
}

void miller_rabin_cleanup(gmp_randstate_t state, mpz_t a, mpz_t x, mpz_t y,
                          mpz_t two, mpz_t num_1, uint *i, mpz_t j, mpz_t s,
                          mpz_t d) {

  state_destroy(state);

  mpz_destroy(a);
  mpz_destroy(x);
  mpz_destroy(y);
  mpz_destroy(two);
  mpz_destroy(num_1);

  i = 0;

  mpz_destroy(j);

  mpz_destroy(s);
  mpz_destroy(d);

  return;
}

void calculate_n(mpz_t n, mpz_t p, mpz_t q) {

  mpz_init(n);

  mpz_mul(n, p, q);

  return;
}

void totient(mpz_t t, mpz_t p, mpz_t q) { // t is the totien function of p, q

  mpz_t a;

  mpz_init(a);

  mpz_init(t);

  mpz_t aux1;
  mpz_t aux2;

  mpz_init(aux1);
  mpz_init(aux2);

  mpz_sub_ui(aux1, p, 1);
  mpz_sub_ui(aux2, q, 1);

  // t = ((p-1) * (q-1)) / gcd(p-1, q-1);
  mpz_mul(t, aux1, aux2);

  mpz_gcd(a, aux1, aux2);

  mpz_div(t, t, a);

  mpz_destroy(aux1);
  mpz_destroy(aux2);

  mpz_destroy(a);

  return;
}

uint calculate_e(mpz_t e, mpz_t t) {

  mpz_init(e);

  // (2 ^ 16) + 1 = 65537
  mpz_set_ui(e, 65537);

  mpz_t aux;

  mpz_init(aux);

  uint i;

  for (i = 0; i < E_TRIES; i++) {

    mpz_gcd(aux, e, t);

    if (!mpz_cmp_ui(aux, 1)) {

      break;
    }

    mpz_add_ui(e, e, 2);
  }

  // Start all over again
  if (i == E_TRIES) {

    i = 0;

    mpz_destroy(aux);
    mpz_destroy(e);

    return (1);
  }

  i = 0;

  mpz_destroy(aux);

  return (0);
}

void mmi(mpz_t d, mpz_t e, mpz_t t) {

  mpz_init(d);

  // mpz_gcdext(gcd, d, tmp, e, t);
  mpz_invert(d, e, t);

  if (mpz_cmp_ui(d, 0) < 0) {
    mpz_add(d, d, t);
  }

  return;
}

void calculate_crt_coefficients(mpz_t dp, mpz_t dq, mpz_t qinv, mpz_t p,
                                mpz_t q, mpz_t d) {

  mpz_init(dp);
  mpz_init(dq);
  mpz_init(qinv);

  mpz_t auxp;
  mpz_t auxq;

  mpz_init(auxp);
  mpz_init(auxq);

  mpz_sub_ui(auxp, p, 1);
  mpz_sub_ui(auxq, q, 1);

  mpz_mod(dp, d, auxp);

  mpz_mod(dq, d, auxq);

  mpz_invert(qinv, q, p);

  mpz_destroy(auxp);
  mpz_destroy(auxq);

  return;
}

/*uchar **write_key(mpz_t n, mpz_t e, mpz_t d) {

  uint pubsize;
  uint privsize;

  pubsize = 0;
  privsize = 0;

  uchar *pubkey;
  uchar *privkey;
  uchar **keypair;

  pubkey = NULL;
  privkey = NULL;
  keypair = NULL;

  pubsize = mpz_sizeinbase(n, 16);
  pubsize += mpz_sizeinbase(e, 16);
  // plus 1 because of the ':'
  pubsize++;

  pubkey = (uchar *)allocate(pubsize * sizeof(uchar));

  pubsize = gmp_snprintf((char *)pubkey, pubsize + 1, "%Zx:%Zx", n, e);

  printf("The public key is [ %d ] > %s\n\n", pubsize, pubkey);

  privsize = mpz_sizeinbase(d, 16);

  privkey = allocate(privsize * sizeof(uchar));

  privsize = gmp_snprintf((char *)privkey, privsize + 1, "%Zx", d);

  // pruintf("The private key is [ * ] > ********************\n\n");
  printf("The private key is [ %d ] > %s\n\n", privsize, privkey);

  pubsize = 0;
  privsize = 0;

  keypair = (uchar **)malloc(2 * sizeof(uchar *));

  keypair[0] = pubkey;
  keypair[1] = privkey;

  return keypair;
}*/

uchar *write_pub_key(mpz_pub pubkey) {

  uint pubsize;

  pubsize = 0;

  uchar *pubstring;

  pubstring = NULL;

  pubsize = mpz_sizeinbase(pubkey.n, 16);
  pubsize += mpz_sizeinbase(pubkey.e, 16);
  // plus 1 because of the ':'
  pubsize++;

  pubstring = (uchar *)allocate(pubsize * sizeof(uchar));

  pubsize = gmp_snprintf((char *)pubstring, pubsize + 1, "%Zx %Zx", pubkey.n,
                         pubkey.e);

  printf("The public key is [ %d ] > %s\n\n", pubsize, pubstring);

  pubsize = 0;

  return pubstring;
}

mpz_pub get_pub_key(char *pubstring) {

  mpz_pub pub_nums;

  uchar *buff;

  buff = (uchar *)allocate((KEY_SIZE / 8) * sizeof(uchar));

  uint i;

  for (i = 0; pubstring[i] != ' '; i++) {

    buff[i] = pubstring[i];
  }
  buff[i] = '\0';

  // now 'i' is the size of the 'n' of the public key in bytes
  // mpz_import(pub_nums.n, i, 1, sizeof(*buff), 0, 0, (char *)buff);
  gmp_sscanf((char *)buff, "%Zx", pub_nums.n);

  uint aux;

  aux = 0;

  for (i++, aux = i; pubstring[i] != '\0'; i++) {

    buff[i - aux] = pubstring[i];
  }
  buff[i] = '\0';

  i = 0;

  aux = 0;

  gmp_sscanf((char *)buff, "%Zx", pub_nums.e);

  string_destroy(&buff);

  return pub_nums;
}

void separate_keys(mpz_keys keypair, mpz_pub *pubkey, mpz_priv *privkey) {

  mpz_init(pubkey->e);
  mpz_init(pubkey->n);

  mpz_init(privkey->p);
  mpz_init(privkey->q);
  mpz_init(privkey->dp);
  mpz_init(privkey->dq);
  mpz_init(privkey->qinv);
  mpz_init(privkey->n);

  mpz_set(pubkey->e, keypair.e);
  mpz_set(pubkey->n, keypair.n);

  mpz_set(privkey->p, keypair.p);
  mpz_set(privkey->q, keypair.q);
  mpz_set(privkey->dp, keypair.dp);
  mpz_set(privkey->dq, keypair.dq);
  mpz_set(privkey->qinv, keypair.qinv);
  mpz_set(privkey->n, keypair.n);

  return;
}

void encrypt_file(uchar **filename, mpz_pub pubkey) {

  uchar *str;

  str = (uchar *)allocate((BLOCK_SIZE + 1) * sizeof(uchar));

  FILE *ifp;

  ifp = fopen((char *)*filename, "rb");

  uchar *foutname;

  foutname = calculate_efoutname(filename);

  FILE *ofp;

  ofp = fopen((char *)foutname, "wb");

  string_destroy(&foutname);

  uint i;
  uint aux;

  i = 0;
  aux = 0;

  uchar *strencrypted;

  while (1) {

    aux = fread((char *)str, sizeof(*str), BLOCK_SIZE, ifp);

    if (aux != BLOCK_SIZE) {

      for (i = aux; i < BLOCK_SIZE; i++) {

        str[i] = '\0';
      }
    }

    strencrypted = encrypt_string(str, aux, pubkey);

    fwrite((char *)strencrypted, sizeof(*strencrypted), BLOCK_SIZE + 1, ofp);

    string_destroy(&strencrypted);

    if (aux != BLOCK_SIZE) {

      break;
    }
  }

  i = 0;
  aux = 0;

  fclose(ifp);

  ifp = NULL;

  fclose(ofp);

  ofp = NULL;

  string_destroy(&str);

  return;
}

// The str will has to be manually freed after, if needed
// Only encrypts strings 255 characters long maximum
uchar *encrypt_string(uchar *str, uint strlength, mpz_pub pubkey) {

  mpz_t num;

  mpz_init(num);

  mpz_import(num, strlength, 1, sizeof(*str), 0, 0, (char *)str);

  encrypt(num, pubkey);

  uchar *strencrypted;

  strencrypted = (uchar *)allocate(KEY_SIZE_BYTES * sizeof(uchar));

  mpz_export((char *)strencrypted, NULL, 1, sizeof(*strencrypted), 1, 0, num);

  mpz_destroy(num);

  return strencrypted;
}

void encrypt(mpz_t num, mpz_pub pubkey) {

  mpz_powm_sec(num, num, pubkey.e, pubkey.n);

  return;
}

uchar *calculate_efoutname(uchar **filename) {

  uint size;

  for (size = 0; filename[0][size] != '\0'; size++)
    ;

  uchar *foutname;

  // Plus 4 to add .rsa
  foutname = (uchar *)allocate((size + 4) * sizeof(uchar));

  uint i;

  for (i = 0; i < size; i++) {

    foutname[i] = filename[0][i];
  }

  i = 0;

  string_destroy(filename);

  foutname[size] = '.';
  foutname[size + 1] = 'r';
  foutname[size + 2] = 's';
  foutname[size + 3] = 'a';

  size = 0;

  return foutname;
}

void decrypt_file(uchar **filename, mpz_priv privkey) {

  uchar *str;

  str = (uchar *)allocate((BLOCK_SIZE + 1) * sizeof(uchar));

  FILE *ifp;

  ifp = fopen((char *)*filename, "rb");

  uchar *foutname;

  foutname = calculate_dfoutname(filename);

  FILE *ofp;

  ofp = fopen((char *)foutname, "wb+");

  string_destroy(&foutname);

  uint aux;
  uint size;

  aux = 0;
  size = BLOCK_SIZE;

  uchar *strdecrypted;

  while (1) {

    aux = fread((char *)str, sizeof(*str), BLOCK_SIZE + 1, ifp);

    if (aux != (BLOCK_SIZE + 1)) {

      break;

      /*for(i=aux ; i < (BLOCK_SIZE + 1); i++){

              str[i] = '\0';
      }*/
    }

    strdecrypted = decrypt_string(str, aux, privkey);

    size = verify_string(strdecrypted);

    fwrite((char *)strdecrypted, sizeof(*strdecrypted), size, ofp);

    string_destroy(&strdecrypted);

    /*if(aux != (BLOCK_SIZE + 1)){

            break;
    }*/
  }

  fclose(ifp);

  ifp = NULL;

  fclose(ofp);

  ofp = NULL;

  string_destroy(&str);

  return;
}

// The str will has to be manually freed after, if needed
// Only decrypts strings 255 characters long maximum
uchar *decrypt_string(uchar *str, uint strlength, mpz_priv privkey) {

  mpz_t num;

  mpz_init(num);

  mpz_import(num, strlength, 1, sizeof(*str), 0, 0, (char *)str);

  decrypt(num, privkey);

  uchar *strdecrypted;

  strdecrypted = (uchar *)allocate(KEY_SIZE_BYTES * sizeof(uchar));

  mpz_export((char *)strdecrypted, NULL, 1, sizeof(*strdecrypted), 1, 0, num);

  mpz_destroy(num);

  return strdecrypted;
}

void decrypt(mpz_t num, mpz_priv privkey) {

  mpz_t m1;
  mpz_t m2;
  mpz_t h;

  mpz_init(m1);
  mpz_init(m2);
  mpz_init(h);

  mpz_powm_sec(m1, num, privkey.dp, privkey.p);

  mpz_powm_sec(m2, num, privkey.dq, privkey.q);

  if (mpz_cmp(m1, m2) < 0) {

    mpz_add(m1, m1, privkey.p);
  }

  mpz_sub(h, m1, m2);

  mpz_mul(h, h, privkey.qinv);

  mpz_mod(h, h, privkey.p);

  mpz_set(num, m2);
  mpz_addmul(num, h, privkey.q);

  mpz_destroy(m1);
  mpz_destroy(m2);
  mpz_destroy(h);

  return;
}

uchar *calculate_dfoutname(uchar **filename) {

  uint size;

  for (size = 0; filename[0][size] != '\0'; size++)
    ;

  uchar *foutname;

  foutname = (uchar *)allocate((size - 4) * sizeof(uchar));

  uint i;

  for (i = 0; i < (size - 4); i++) {

    foutname[i] = filename[0][i];
  }

  i = 0;

  string_destroy(filename);

  size = 0;

  return foutname;
}

uint verify_string(uchar *str) {

  uint size;

  for (size = BLOCK_SIZE - 1; size >= 0; size--) {

    if (str[size] != '\0') {

      break;
    }
  }

  return size + 1;
}

void *allocate(uint size) {

  uchar *str;

  str = (uchar *)malloc((size + 1) * sizeof(uchar));

  uint i;

  for (i = 0; i <= size; i++) {

    str[i] = '\0';
  }

  i = 0;

  return (void *)str;
}

void state_destroy(gmp_randstate_t state) {

  gmp_randclear(state);

  gmp_randstate_t aux;

  gmp_randinit_default(aux);

  gmp_randinit_set(state, aux);

  gmp_randclear(aux);

  gmp_randclear(state);

  return;
}

void mpz_destroy(mpz_t var) {

  mpz_set_ui(var, 0);

  mpz_clear(var);

  return;
}

void string_destroy(uchar **key) {

  uint i;

  for (i = 0; key[0][i] != 0; i++) {

    key[0][i] = 0;
  }

  i = 0;

  free((void *)*key);

  *key = NULL;

  return;
}

/*void keypair_destroy(uchar ***keypair) {

  free(*keypair);

  *keypair = NULL;

  return;
}*/

/*void structs_destroy(mpz_pub pubkey, mpz_priv privkey) {

  mpz_destroy(pubkey.e);
  mpz_destroy(pubkey.n);

  mpz_destroy(privkey.d);
  mpz_destroy(privkey.n);

  return;
}*/

void mpz_keys_destroy(mpz_keys keypair) {

  mpz_destroy(keypair.e);
  mpz_destroy(keypair.p);
  mpz_destroy(keypair.q);
  mpz_destroy(keypair.dp);
  mpz_destroy(keypair.dq);
  mpz_destroy(keypair.qinv);
  mpz_destroy(keypair.n);

  return;
}

void mpz_pub_destroy(mpz_pub pubkey) {

  mpz_destroy(pubkey.e);
  mpz_destroy(pubkey.n);

  return;
}

void mpz_priv_destroy(mpz_priv privkey) {

  mpz_destroy(privkey.p);
  mpz_destroy(privkey.q);
  mpz_destroy(privkey.dp);
  mpz_destroy(privkey.dq);
  mpz_destroy(privkey.qinv);
  mpz_destroy(privkey.n);

  return;
}
