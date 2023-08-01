#ifndef _TRANSLATE_H
#define _TRANSLATE_H

#include "XEDParse.h"
#include "Parser.h"

LONGLONG TranslateRelativeCip(XEDPARSE* Parse, ULONGLONG Value, bool Signed);
xed_encoder_operand_t OperandToXed(InstOperand* Operand);
void InstructionToXed(Inst* Instruction, xed_state_t Mode, xed_encoder_instruction_t* XedInst, unsigned int EffectiveWidth);
bool TryEncode(XEDPARSE* Parse, xed_state_t State, Inst* Instruction, unsigned int Bits);
bool TryRecode(XEDPARSE* Parse, xed_state_t State, Inst* Instruction, unsigned int Bits);
bool Translate(XEDPARSE* Parse, xed_state_t State, Inst* Instruction);
#endif
