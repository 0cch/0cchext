#ifndef __0CCHEXT_ASSEMBLER_BACKEND_H__
#define __0CCHEXT_ASSEMBLER_BACKEND_H__

#include <Windows.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

constexpr size_t kMaxAssemblerInstructionLength = 255;

struct AssemblerRequest
{
	std::string instruction;
	uint64_t rip;
	bool x64;
};

struct AssemblerResult
{
	std::vector<uint8_t> bytes;
	std::string normalized_instruction;
	std::string error;
};

class IAssemblerBackend
{
public:
	virtual ~IAssemblerBackend() = default;
	virtual const char *Name() const = 0;
	virtual HRESULT Assemble(const AssemblerRequest &request, AssemblerResult &result) = 0;
};

std::unique_ptr<IAssemblerBackend> CreateLegacyXedBackend();

#endif
