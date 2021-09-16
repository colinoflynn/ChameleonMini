#ifndef __AES_CMAC_H__
#define __AES_CMAC_H__

int aes_cmac8(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length);

#endif
