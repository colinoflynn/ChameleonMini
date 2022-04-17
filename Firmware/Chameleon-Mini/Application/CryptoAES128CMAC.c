/*
The MIT License (MIT)

Copyright (c) 2015 flexibity-team

The following file is derived/copied from https://github.com/flexibity-team/AES-CMAC-RFC
which was posted under an MIT license. The additional modifications are made
available under the same license and are:

Copyright (c) 2021 Colin O'Flynn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <string.h>
#include <avr/pgmspace.h>

#include "../Configuration.h"
#include "../Memory.h"
#include "../Common.h"
#include "../Random.h"
#include "CryptoAES128.h"

/* Only add the CMAC code if we are building the MifarePlus extensions */
#ifdef CONFIG_MF_DESFIRE_MFP_EXTENSIONS

#define BLOCK_SIZE 16
#define LAST_INDEX (BLOCK_SIZE - 1)


/* For CMAC Calculation */
static unsigned const char const_Rb[BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 };
static unsigned const char const_Zero[BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


void xor_128(const unsigned char *a, const unsigned char *b, unsigned char *out) {
	int i;
	for (i = 0; i < BLOCK_SIZE; i++) {
		out[i] = a[i] ^ b[i];
	}
}

static void padding_AES(const unsigned char *lastb, unsigned char *pad, int length) {
	int j;
	length = length % BLOCK_SIZE;

	if(length == 0){
		memcpy(pad, lastb, BLOCK_SIZE);
		return;
	}

	/* original last block */
	for (j = 0; j < BLOCK_SIZE; j++) {
		if (j < length) {
			pad[j] = lastb[j];
		} else {
			pad[j] = 0x00;
		}
	}
}


/* AES-CMAC Generation Function */

static void leftshift_onebit(const unsigned char *input, unsigned char *output) {
	int i;
	unsigned char overflow = 0;

	for (i = LAST_INDEX; i >= 0; i--) {
		output[i] = input[i] << 1;
		output[i] |= overflow;
		overflow = (input[i] & 0x80) ? 1 : 0;
	}
	return;
}

static void generate_subkey(const unsigned char *key, unsigned char *K1, unsigned char *K2) {
	unsigned char L[BLOCK_SIZE];
	unsigned char tmp[BLOCK_SIZE];

    CryptoAESEncryptBlock(const_Zero, L, key, false);

	if ((L[0] & 0x80) == 0) { /* If MSB(L) = 0, then K1 = L << 1 */
		leftshift_onebit(L, K1);
	} else { /* Else K1 = ( L << 1 ) (+) Rb */

		leftshift_onebit(L, tmp);
		xor_128(tmp, const_Rb, K1);
	}

	if ((K1[0] & 0x80) == 0) {
		leftshift_onebit(K1, K2);
	} else {
		leftshift_onebit(K1, tmp);
		xor_128(tmp, const_Rb, K2);
	}
	return;
}

static void padding(const unsigned char *lastb, unsigned char *pad, int length) {
	int j;

	/* original last block */
	for (j = 0; j < BLOCK_SIZE; j++) {
		if (j < length) {
			pad[j] = lastb[j];
		} else if (j == length) {
			pad[j] = 0x80;
		} else {
			pad[j] = 0x00;
		}
	}
}

void AES_CMAC(const unsigned char *key, const unsigned char *input, int length, unsigned char *mac) {
	unsigned char X[BLOCK_SIZE], Y[BLOCK_SIZE], M_last[BLOCK_SIZE], padded[BLOCK_SIZE];
	unsigned char K1[BLOCK_SIZE], K2[BLOCK_SIZE];
	int n, i, flag;
	generate_subkey(key, K1, K2);

	n = (length + LAST_INDEX) / BLOCK_SIZE; /* n is number of rounds */

	if (n == 0) {
		n = 1;
		flag = 0;
	} else {
		if ((length % BLOCK_SIZE) == 0) { /* last block is a complete block */
			flag = 1;
		} else { /* last block is not complete block */
			flag = 0;
		}
	}

	if (flag) { /* last block is complete block */
		xor_128(&input[BLOCK_SIZE * (n - 1)], K1, M_last);
	} else {
		padding(&input[BLOCK_SIZE * (n - 1)], padded, length % BLOCK_SIZE);
		xor_128(padded, K2, M_last);
	}

	memset(X, 0, BLOCK_SIZE);
	for (i = 0; i < n - 1; i++) {
		xor_128(X, &input[BLOCK_SIZE * i], Y); /* Y := Mi (+) X  */
		CryptoAESEncryptBlock(Y, X, key, false);
	}

	xor_128(X, M_last, Y);
	CryptoAESEncryptBlock(Y, X, key, false);

	memcpy(mac, X, BLOCK_SIZE);
}


int CryptoAESCMAC(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length) {
    memset(mac, 0x00, 16);

    AES_CMAC(key, input, length, mac);
    
    return 0;
}

int CryptoAESCMAC8(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length) {
    uint8_t cmac_tmp[16] = {0};
    memset(mac, 0x00, 8);

    int res = CryptoAESCMAC(iv, key, input, cmac_tmp, length);
    if (res)
        return res;

    for (int i = 0; i < 8; i++)
        mac[i] = cmac_tmp[i * 2 + 1];

    return 0;
}

#endif