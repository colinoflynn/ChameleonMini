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

typedef enum DESFIRE_FIRMWARE_ENUM_PACKING {

    /* NO_COMMAND_TO_CONTINUE = 0x00, */ //This gets defined in DESFire instructions which are pulled in
    CMD_MFP_EV1_AUTH1 = 0x70,
    CMD_MFP_EV1_AUTH2 = 0x72,
    CMD_MFP_READ_EMM = 0x31,

    /* Space for undocumented command codes --
     * Need command codes and parameters to make these work moving forward: */
    //CMD_READ_SIGNATURE /* See page 87 of AN12343.pdf (for Mifare DESFire Light tags) */

} MFPCommandType;

typedef uint16_t (*InsCodeHandlerFunc)(uint8_t *Buffer, uint16_t ByteCount);

typedef struct {
    MFPCommandType      insCode;
    InsCodeHandlerFunc  insFunc;
    const __flash char *insDesc;
} MFPCommand;

/* MFP EV1 Commands */
uint16_t MFPEV1AuthFirst(uint8_t* Buffer, uint16_t ByteCount);
uint16_t MFPEV1AuthContinue(uint8_t* Buffer, uint16_t ByteCount);
uint16_t MFPEV1ReadEMM(uint8_t* Buffer, uint16_t ByteCount);

extern const __flash MFPCommand MFPCommandSet[];

/* Helper and batch process functions */
uint16_t CallInstructionHandler(uint8_t *Buffer, uint16_t ByteCount);
uint16_t ExitWithStatus(uint8_t *Buffer, uint8_t StatusCode, uint16_t DefaultReturnValue);
uint16_t CmdNotImplemented(uint8_t *Buffer, uint16_t ByteCount);


#endif
