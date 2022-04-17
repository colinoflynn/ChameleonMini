/*
The DESFire stack portion of this firmware source
is free software written by Maxie Dion Schmidt (@maxieds):
You can redistribute it and/or modify
it under the terms of this license.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

The complete source distribution of
this firmware is available at the following link:
https://github.com/maxieds/ChameleonMiniFirmwareDESFireStack.

Based in part on the original DESFire code created by
@dev-zzo (GitHub handle) [Dmitry Janushkevich] available at
https://github.com/dev-zzo/ChameleonMini/tree/desfire.

This notice must be retained at the top of all source files where indicated.
*/

/*
 * MFPFireInstructions.c
 * Colin O'Flynn (github.com/colinoflynn)
 * Maxie D. Schmidt (github.com/maxieds)
 */

#ifdef CONFIG_MF_DESFIRE_MFP_EXTENSIONS

#include <string.h>
#include <avr/pgmspace.h>

#include "../../Configuration.h"
#include "../../Memory.h"
#include "../../Common.h"
#include "../../Random.h"
#include "../CryptoAES128.h"
#include "../CryptoAES128CMAC.h"

#include "DESFireInstructions.h"
#include "MFPInstructions.h"
#include "DESFirePICCControl.h"
#include "DESFireCrypto.h"
#include "DESFireStatusCodes.h"
#include "DESFireLogging.h"
#include "DESFireUtils.h"
#include "DESFireMemoryOperations.h"
#include "../MifareDESFire.h"

static uint8_t MFPRandomA[16] = {0};
static uint8_t MFPRandomB[16] = {0x43, 0x48, 0xa5, 0xf2, 0xc1, 0x3f, 0xd2, 0xd6, 0x41, 0xb4, 0x68, 0xa1, 0x47, 0x71, 0x28, 0x8c};

static uint8_t kenc[16];
static uint8_t kmac[16];

static CryptoAESConfig_t ctx_fixed;
static CryptoAESConfig_t ctx_kenc;
static CryptoAESConfig_t ctx_kmac;

/* Currently the sector data is initialized from an external file */
#include "../../../MFPSecrets.h"
static uint8_t data_store[] = DATA_STORE_INIT_VALUE;
static uint8_t fixedkey[16] = SECTOR_FIXED_KEY;

uint16_t MFPEV1AuthFirst(uint8_t* Buffer, uint16_t ByteCount) {

    //if (ByteCount != 4) {
    //    Buffer[0] = STATUS_LENGTH_ERROR;
    //    return DESFIRE_STATUS_RESPONSE_SIZE;
    //}

    const char *debugPrintStr = PSTR("MFP: EV1 Auth First");
    LogDebuggingMsg(debugPrintStr);

    uint16_t ki = Buffer[1] | (uint16_t)(Buffer[2] << 8);   

    CryptoAESGetConfigDefaults(&ctx_fixed);
    CryptoAESInitContext(&ctx_fixed);
    CryptoAESEncryptBuffer(16, MFPRandomB, &Buffer[1], NULL, fixedkey);

    Buffer[0] = 0x90;

    return DESFIRE_STATUS_RESPONSE_SIZE + 16;
}


uint16_t MFPEV1AuthContinue(uint8_t* Buffer, uint16_t ByteCount) {

    //if (ByteCount != 33) {
    //    Buffer[0] = STATUS_LENGTH_ERROR;
    //    return DESFIRE_STATUS_RESPONSE_SIZE;
    //}

    uint8_t MFPRandomAB[32];

    CryptoAESInitContext(&ctx_fixed);
    CryptoAESDecryptBuffer(32, MFPRandomAB, &Buffer[1], NULL, fixedkey);  

    Buffer[0] = 0x90;

    memcpy(MFPRandomA, MFPRandomAB, 16);

    if (memcmp(&MFPRandomAB[16], &MFPRandomB[1], 15) != 0){
        Buffer[0] = STATUS_INTEGRITY_ERROR; /* Not sure on correct error, mostly a flag externally */
        return DESFIRE_STATUS_RESPONSE_SIZE;
    }

    MFPRandomAB[0] = 192; /*TODO TI - what should this be?*/
    MFPRandomAB[1] = 104;
    MFPRandomAB[2] = 13;
    MFPRandomAB[3] = 158;

    memcpy(&MFPRandomAB[4], &MFPRandomA[1], 15);
    MFPRandomAB[19] = MFPRandomA[0];

    MFPRandomAB[20] = 0; /*PIC*/
    MFPRandomAB[21] = 0; /*PIC?*/
    MFPRandomAB[22] = 0; /*PIC?*/
    MFPRandomAB[23] = 0; /*PIC?*/
    MFPRandomAB[24] = 0; /*PIC?*/
    MFPRandomAB[25] = 0; /*PIC?*/

    MFPRandomAB[26] = 0; /*PCD*/
    MFPRandomAB[27] = 0; /*PCD?*/
    MFPRandomAB[28] = 0; /*PCD?*/
    MFPRandomAB[29] = 0; /*PCD?*/
    MFPRandomAB[30] = 0; /*PCD?*/
    MFPRandomAB[31] = 0; /*PCD?*/       

    CryptoAESInitContext(&ctx_fixed);
    CryptoAESEncryptBuffer(32, MFPRandomAB, &Buffer[1], NULL, fixedkey);      

    kenc[0] = MFPRandomA[11];
    kenc[1] = MFPRandomA[12];
    kenc[2] = MFPRandomA[13];
    kenc[3] = MFPRandomA[14];
    kenc[4] = MFPRandomA[15];    
    kenc[5] = MFPRandomB[11];
    kenc[6] = MFPRandomB[12];
    kenc[7] = MFPRandomB[13];
    kenc[8] = MFPRandomB[14];
    kenc[9] = MFPRandomB[15];
    kenc[10] = MFPRandomA[4] ^ MFPRandomB[4];
    kenc[11] = MFPRandomA[5] ^ MFPRandomB[5];
    kenc[12] = MFPRandomA[6] ^ MFPRandomB[6];
    kenc[13] = MFPRandomA[7] ^ MFPRandomB[7];
    kenc[14] = MFPRandomA[8] ^ MFPRandomB[8];
    kenc[15] = 0x11;


    kmac[0] = MFPRandomA[7];
    kmac[1] = MFPRandomA[8];
    kmac[2] = MFPRandomA[9];
    kmac[3] = MFPRandomA[10];
    kmac[4] = MFPRandomA[11];    
    kmac[5] = MFPRandomB[7];
    kmac[6] = MFPRandomB[8];
    kmac[7] = MFPRandomB[9];
    kmac[8] = MFPRandomB[10];
    kmac[9] = MFPRandomB[11];
    kmac[10] = MFPRandomA[0] ^ MFPRandomB[0];
    kmac[11] = MFPRandomA[1] ^ MFPRandomB[1];
    kmac[12] = MFPRandomA[2] ^ MFPRandomB[2];
    kmac[13] = MFPRandomA[3] ^ MFPRandomB[3];
    kmac[14] = MFPRandomA[4] ^ MFPRandomB[4];
    kmac[15] = 0x22;

    CryptoAESGetConfigDefaults(&ctx_kenc);
    CryptoAESInitContext(&ctx_kenc);
    CryptoAESEncryptBuffer(16, kenc, kenc, NULL, fixedkey);
    CryptoAESGetConfigDefaults(&ctx_kmac);
    CryptoAESInitContext(&ctx_kmac);
    CryptoAESEncryptBuffer(16, kmac, kmac, NULL, fixedkey);

    return DESFIRE_STATUS_RESPONSE_SIZE + 32;
}

uint16_t MFPEV1ReadEMM(uint8_t* Buffer, uint16_t ByteCount) {

    uint8_t iv[16] = {0};
    uint8_t macdata[128];
    uint8_t datalen= 16*3;

    Buffer[0] = 0x90;//Respond OK

    iv[0] = 192; //TI
    iv[1] = 104;
    iv[2] = 13;
    iv[3] = 158;
    iv[4] = 1; //rdcnt
    iv[8] = 1; //rdcnt
    iv[12] = 1; //rdcnt    
    CryptoAESInitContext(&ctx_kenc);
    CryptoAESEncryptBuffer(datalen, data_store, &Buffer[1], iv, kenc);


    macdata[0] = Buffer[0];
    macdata[1] = 1; //CTR LSB
    macdata[2] = 0; //CTR BSB
    macdata[3] = 192; //TI 192, 104, 13, 158
    macdata[4] = 104;
    macdata[5] = 13;
    macdata[6] = 158;
    macdata[7] = 0x18; //block (TODO - should not be fixed)
    macdata[8] = 0;
    macdata[9] = 3; //blockcnt (TODO - should not be fixed)
    memcpy(&macdata[10], &Buffer[1], datalen);

    CryptoAESCMAC8(NULL, kmac, macdata, &Buffer[datalen+1], datalen+10);

    return DESFIRE_STATUS_RESPONSE_SIZE + 56;
}

#endif /* CONFIG_MF_DESFIRE_SUPPORT */
