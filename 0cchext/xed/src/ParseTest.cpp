#include "ParseTest.h"
#include "Register.h"
#include <stdio.h>
#include <strsafe.h>

void OperandToString(char* Buffer, size_t BufferChars, InstOperand* Operand)
{
    switch(Operand->Type)
    {
    case OPERAND_INVALID:
        StringCchCopyA(Buffer, BufferChars, "(INVALID OPERAND)");
        break;

    case OPERAND_REG:
        StringCchCopyA(Buffer, BufferChars, RegToString(Operand->Reg.Reg));
        break;

    case OPERAND_IMM:
        if(Operand->Imm.Signed && Operand->Imm.simm < 0)
            StringCchPrintfA(Buffer, BufferChars, "-0x%llX/%d", (~Operand->Imm.imm) + 1, Operand->Size);
        else
            StringCchPrintfA(Buffer, BufferChars, "0x%llX/%d", Operand->Imm.imm, Operand->Size);
        break;

    case OPERAND_MEM:
    {
        char base[64];
        char scale[64];

        memset(base, 0, sizeof(base));
        memset(scale, 0, sizeof(scale));

        if(Operand->Mem.Base)
            sprintf(base, "%s + ", RegToString(Operand->Mem.BaseVal));

        if(Operand->Mem.Index)
            sprintf(scale, "%s * %u + ", RegToString(Operand->Mem.IndexVal), (unsigned int)Operand->Mem.ScaleVal);

        StringCchPrintfA(Buffer, BufferChars, "%s ptr %s:[%s%s0x%llX/%d]",
                OpsizeToString(Operand->Size),
                RegToString(Operand->Segment),
                base,
                scale,
                Operand->Mem.DispVal,
                OpsizeToBits(Operand->Mem.DispWidth));
    }
    break;

    case OPERAND_SEGSEL:
        StringCchPrintfA(Buffer, BufferChars, "0x%llX", Operand->Sel.Offset);
        break;
    }
}

void InstructionToString(char* Buffer, size_t BufferChars, Inst* Instruction)
{
    // Add the prefix if there was one
    if(Instruction->Prefix != PREFIX_NONE)
    {
        StringCchCatA(Buffer, BufferChars, PrefixToString(Instruction->Prefix));
        StringCchCatA(Buffer, BufferChars, " ");
    }

    // Append mnemonic
    StringCchCatA(Buffer, BufferChars, Instruction->Mnemonic);

    // Append all operands
    if(Instruction->OperandCount > 0)
    {
        StringCchCatA(Buffer, BufferChars, " ");

        for(int i = 0; i < Instruction->OperandCount; i++)
        {
            char op[XEDPARSE_MAXBUFSIZE];
            OperandToString(op, sizeof(op), &Instruction->Operands[i]);

            StringCchCatA(Buffer, BufferChars, op);
            StringCchCatA(Buffer, BufferChars, ", ");
        }

        // Remove the final trailing comma
        *strrchr(Buffer, ',') = '\0';
    }
}
