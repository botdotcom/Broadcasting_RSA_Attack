#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include "lib/bigd.h"


int main() {



    BIGD ciphertext1, ciphertext2, ciphertext3, modulus1, modulus2, modulus3, product, product1, product2, product3, result, tmp, final,mod1, mod2, mod3;
    unsigned char *plaintext =  (char*) malloc (256);

    ciphertext1  = bdNew();
    ciphertext2  = bdNew();
    ciphertext3  = bdNew();
    modulus1     = bdNew();
    modulus2     = bdNew();
    modulus3     = bdNew();
    product      = bdNew();
    product1     = bdNew();
    product2     = bdNew();
    product3     = bdNew();
    result       = bdNew();
    tmp          = bdNew();
    final        = bdNew();
    mod1         = bdNew();
    mod2         = bdNew();
    mod3         = bdNew();

    char *buf1, *buf2, *buf3;
    size_t bufsize = 32;

    printf("Enter three ciphertext strings in hex, each on a new line:\n");

    buf1 = (char *) malloc (bufsize * sizeof(char));
    getline(&buf1, &bufsize, stdin);
    buf2 = (char *) malloc (bufsize * sizeof(char));
    getline(&buf2, &bufsize, stdin);
    buf3 = (char *) malloc (bufsize * sizeof(char));
    getline(&buf3, &bufsize, stdin);

    bdConvFromHex(ciphertext1, buf1);
    bdConvFromHex(ciphertext2, buf2);
    bdConvFromHex(ciphertext3, buf3);


    bdConvFromHex(modulus1, "009623511e6769644d693e89f692ffc2558eef121d42ca98699781e139e29c2e1aa58d8883bbdba41165fdeb85a9a5648fc29a65d59e9401694dd11ae205f0ce3b");
    bdConvFromHex(modulus2, "00ad4bc0f980f4523f490fc40c12efcecc1e8af67890b6562449876e8e091e861cda699e5a8eb309b0a9d6b293100c1229fbd18a5951f33b6fbab1fd8d90f7c829");
    bdConvFromHex(modulus3, "00b7223364d88353ec02b0850e8a01d2ba9ca2663c32c15df7b596406c6fc1c171ac965a554b8b338f4bb046c543937b4b19c699864f1d0dd4be0177eccce0bb57");

    bdMultiply(tmp, modulus1, modulus2);
    bdMultiply(product, tmp, modulus3);

    bdMultiply(product1, modulus2, modulus3);
    bdMultiply(product2, modulus1, modulus3);
    bdMultiply(product3, modulus1, modulus2);

    bdModInv(mod1, product1, modulus1);
    bdModInv(mod2, product2, modulus2);
    bdModInv(mod3, product3, modulus3);

    bdModMult(result, ciphertext1, product1, product);
    bdModMult(final, result, mod1, product);
    bdModMult(result, ciphertext2, product2, product);
    bdModMult(tmp, result, mod2, product);
    bdAdd(final, final, tmp);
    bdModMult(result, ciphertext3, product3, product);
    bdModMult(tmp, result, mod3, product);
    bdAdd(result, final, tmp);
    bdModulo(final, result, product);

    bdCubeRoot(tmp, final);

    bdConvToHex(tmp,plaintext,256);

    unsigned int integer;
    char buffer[128];
    char *iter = buffer;
    char *last = buffer + sizeof(buffer);

    while (sscanf(plaintext, "%2x", &integer) == 1 && iter < last) {
        *iter++ = integer;
        plaintext += 2;
    }

    for (iter = buffer; iter < last; iter++) {
        if (isprint(*iter)) {
            printf("%c", *iter);
        }
        else {
            break;
        }
    }
    printf("\n");

    return 0;
}


























































