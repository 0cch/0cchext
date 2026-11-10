#include "stdafx.h"
#include "assembler_backend.h"
#include "xed/src/XEDParse.h"

namespace
{
bool XEDPARSE_CALL UnknownCode(const char *text, ULONGLONG *value)
{
	UNREFERENCED_PARAMETER(text);
	UNREFERENCED_PARAMETER(value);
	return false;
}

class LegacyXedBackend final : public IAssemblerBackend
{
public:
	const char *Name() const override
	{
#ifdef XEDPARSE_NEW_XED
		return "Intel XED 2026 (XEDParse)";
#else
		return "Intel XED legacy (XEDParse)";
#endif
	}

	HRESULT Assemble(const AssemblerRequest &request, AssemblerResult &result) override
	{
		result = {};
		if (request.instruction.empty() || request.instruction.size() > kMaxAssemblerInstructionLength) {
			result.error = "Instruction is empty or too long.";
			return E_INVALIDARG;
		}

		XEDPARSE xed = {0};
		xed.x64 = request.x64;
		xed.cip = request.rip;
		xed.cbUnknown = UnknownCode;
		if (strcpy_s(xed.instr, request.instruction.c_str()) != 0) {
			result.error = "Instruction is too long.";
			return E_INVALIDARG;
		}

		if (XEDParseAssemble(&xed) != XEDPARSE_OK) {
			result.error = xed.error[0] != '\0' ? xed.error : "Cannot assemble this code.";
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		}
		if (xed.dest_size > sizeof(xed.dest)) {
			result.error = "Assembler returned an invalid instruction length.";
			return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		}

		result.bytes.assign(xed.dest, xed.dest + xed.dest_size);
		result.normalized_instruction = xed.error;
		return S_OK;
	}
};
}

std::unique_ptr<IAssemblerBackend> CreateLegacyXedBackend()
{
	return std::make_unique<LegacyXedBackend>();
}
