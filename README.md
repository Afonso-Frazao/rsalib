## DISCLAIMER

**This library has not been professionally tested for security or efficiency.** It is provided as-is, without any warranties or guarantees. The library may contain vulnerabilities or flaws that could be exploited, leading to potential security risks. **It is not intended for professional or production use.** Use at your own risk, and do not rely on this library for any critical security applications.


# RSALIB C Library

## Overview

Basic C library for cryptographic purposes. The library includes implementations for the cryptographic algorithms:

- Asymmetric encryption (RSA)
- Padding scheme (OAEP)
- Hash functions (SHA-256)
- Message Authentication Codes (HMAC)
- Digital Signatures (RSA)
- Password securing (PBKDF2)


## Functions

- Function usage example in main function in rsa.c file

- Key generation, storing / retrieval / destroying:
  generate_keys
  separate_keys
  password_protected_seed
  get_salt
  write_pub_key
  get_pub_key
  keypair_destroy

- Encryption:
  encrypt_string
  decrypt_string

- Hashing:
  sha256
  mgf1

- Padding:
  oaep_encode
  oaep_decode

- Password securing:
  pbkdf2

- Message signing:
  hmac
  extract_hash
  sign_oaep
  verify_signature

- Random number / string generation:
  generate_seed_string

- Memory management:
  allocate
  string_destroy


### Cloning the Repository

```bash
git clone https://github.com/Afonso-Frazao/rsalib.bit
cd rsalib
```

### Compile from source

```bash
	gcc -O3 -c rsa.c sha.c oaep.c sign.c pbkdf2.c
	ar rcs librsalib.a rsa.o sha.o oaep.o sign.o pbkdf2.o
```
- Or alternatively

```bash
  make lib
  make ar
```

## How to include in your project

- Include the header in your program
- Include the compiled library with the corresponding path
- Also include GNU's GMP library, because it was used in this project

```C
#include "/path/to/rsalib.h"
```

```bash
gcc -o yourapp yourapp.c -I/path/to/rsalib -L/path/to/rsalib -lrsalib -lgmp
```

## TODO list

- PSK based cryptographic algorithm
- Diffie-Hellman key exchange
- SHA-512

## License

This project is licensed under the GNU General Public License v3.0 or later. See the [LICENSE](LICENSE) file for details.

## Credits

- Great SHA256 website that helped me to understand the algorithm: [sha256algorithm](https://sha256algorithm.com)
