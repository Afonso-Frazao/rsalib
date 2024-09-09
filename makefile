main:
	gcc -Wall -O3 -o rsa rsa.c sha.c oaep.c sign.c pbkdf2.c -lgmp

dbg:
	gcc -Wall -g -o rsa rsa.c sha.c oaep.c sign.c pbkdf2.c -lgmp

val:
	valgrind ./rsa

full:
	valgrind --leak-check=full --show-leak-kinds=all --show-error-list=all ./rsa


# Compile the library with 'make lib' command
lib:
	gcc -O3 -c rsa.c sha.c oaep.c sign.c pbkdf2.c

# Archive the library
arch:
	ar rcs librsalib.a rsa.o sha.o oaep.o sign.o pbkdf2.o
