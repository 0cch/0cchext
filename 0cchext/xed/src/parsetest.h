#ifndef _PARSETEST_H
#define _PARSETEST_H

#include "Parser.h"

void OperandToString(char* Buffer, size_t BufferChars, InstOperand* Operand);
void InstructionToString(char* Buffer, size_t BufferChars, Inst* Instruction);
#endif
