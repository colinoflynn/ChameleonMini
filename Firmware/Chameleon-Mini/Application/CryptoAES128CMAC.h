#ifndef __AES_CMAC_H__
#define __AES_CMAC_H__

/* This is the normal CMAC used by e.g. AES authentication on MFP in AES Mode */
int CryptoAESCMAC8(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length);

int CryptoAESCMAC(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length);

#endif
