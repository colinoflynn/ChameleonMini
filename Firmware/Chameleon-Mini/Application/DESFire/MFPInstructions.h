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
 * DESFireInstructions.h :
 * Maxie D. Schmidt (github.com/maxieds)
 */

#ifndef __MFP_INS_COMMANDS_H__
#define __MFP_INS_COMMANDS_H__

/* MFP EV1 Commands */
uint16_t MFPEV1AuthFirst(uint8_t* Buffer, uint16_t ByteCount);
uint16_t MFPEV1AuthContinue(uint8_t* Buffer, uint16_t ByteCount);
uint16_t MFPEV1ReadEMM(uint8_t* Buffer, uint16_t ByteCount);

#endif
