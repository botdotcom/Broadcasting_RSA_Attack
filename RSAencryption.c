#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "bigd.h"

int main(void){
    // declaring all the required variables
    BIGD M, e, n1, n2, n3, c1, c2, c3, temp, c1d, c2d, c3d;   // big-digits from library
    M = bdNew();    // message M
    e = bdNew();    // exponent e
    n1 = bdNew();   // modulus n1
    n2 = bdNew();   // modulus n2
    n3 = bdNew();   // modulus n3
    c1 = bdNew();   // ciphertext c1
    c2 = bdNew();   // ciphertext c2
    c3 = bdNew();   // ciphertext c3
    temp = bdNew(); // variable for reusing as temporary
    unsigned char plaintext[257], phex[515];    // plaintext in string and hex format respectively
    int i, j;   // temporary iterators

    // get input from user
    printf("Enter the message string to be encrypted: \n");
    scanf("%[^\n]s", plaintext);
    printf("\nMessage obtained...");

    // convert string plaintext to hexadecimal format
    memset(phex, 0, sizeof(phex));

    for(i=0, j=0; i<strlen(plaintext); i++, j+=2){
        sprintf((char*)phex+j, "%02x", plaintext[i]);
    }
    phex[j] = '\0';

    // convert plaintext hexadecimal to decimal
    bdConvFromHex(M, phex);

    // convert given hexadecimal moduli to decimal format
    bdConvFromHex(n1, "009623511e6769644d693e89f692ffc2558eef121d42ca98699781e139e29c2e1aa58d8883bbdba41165fdeb85a9a5648fc29a65d59e9401694dd11ae205f0ce3b");
    bdConvFromHex(n2, "00ad4bc0f980f4523f490fc40c12efcecc1e8af67890b6562449876e8e091e861cda699e5a8eb309b0a9d6b293100c1229fbd18a5951f33b6fbab1fd8d90f7c829");
    bdConvFromHex(n3, "00b7223364d88353ec02b0850e8a01d2ba9ca2663c32c15df7b596406c6fc1c171ac965a554b8b338f4bb046c543937b4b19c699864f1d0dd4be0177eccce0bb57");

    printf("\n---------- PUBLIC KEY ----------");
    printf("\nModuli:\n");

    bdPrintDecimal("n1 = ", n1, "\n");
    bdPrintDecimal("n2 = ", n2, "\n");
    bdPrintDecimal("n3 = ", n3, "\n");

    bdSetShort(e, 3);
    printf("\nExponent:\n");
    bdPrintHex("e = ", e, "\n");

    // checking that (n1, e), (n2, e) and (n3, e) are coprimes
    printf("\n--------- CHECKS ----------\n");
    bdGcd(temp, n1, e);
    bdPrintDecimal("gcd(n1, e) = ", temp, "\n");
    bdGcd(temp, n2, e);
    bdPrintDecimal("gcd(n2, e) = ", temp, "\n");
    bdGcd(temp, n3, e);
    bdPrintDecimal("gcd(n3, e) = ", temp, "\n");

    // encryption begins here using C = M^e mod N
    bdModExp_ct(c1, M, e, n1);
    bdModExp_ct(c2, M, e, n2);
    bdModExp_ct(c3, M, e, n3);

    printf("\n--------- CIPHERTEXTS ----------\n");
    bdPrintHex("c1 = ", c1, "\n");
    bdPrintHex("c2 = ", c2, "\n");
    bdPrintHex("c3 = ", c3, "\n");

    // free memory
    bdFree(&M);
    bdFree(&e);
    bdFree(&n1);
    bdFree(&n2);
    bdFree(&n3);
    bdFree(&c1);
    bdFree(&c2);
    bdFree(&c3);

    return 0;
}