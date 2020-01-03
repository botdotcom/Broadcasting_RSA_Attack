# Broadcasting_RSA_Attack
##Cryptanalysis project for CS 265 at SJSU

The RSAencryption.c program encrypts a given text using RSA algorithm. The crt.c program decrypts a RSA encrypted ciphertext.

To run encryption, open a terminal in the folder and run the following commands before input plaintext:
```
$ gcc RSAencryption.c bigd.c bigd.h bigdigits.c bigdigits.h bigdtypes.h -o encrypt
$ ./encrypt
```

To run decryption, open another terminal in the folder and run the following commands before input ciphertext:
```
$ gcc crt.c bigd.c bigd.h bigdigits.c bigdigits.h bigdtypes.h -o decrypt
$ ./decrypt
```

