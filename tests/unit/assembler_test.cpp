#include <Windows.h>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <vector>

#include "assembler_backend.h"

static std::unique_ptr<IAssemblerBackend> g_backend;

static std::vector<unsigned char> Assemble(const char *text, bool x64)
{
	AssemblerRequest request;
	request.instruction = text;
	request.rip = 0x1000;
	request.x64 = x64;
	AssemblerResult result;
	if (!g_backend) {
		std::cerr << "assembler backend creation failed\n";
		std::exit(1);
	}
	const HRESULT hr = g_backend->Assemble(request, result);
	if (FAILED(hr)) {
		std::cerr << "assembler failed: " << text << " error=" << result.error << "\n";
		std::exit(1);
	}
	return result.bytes;
}

static void AssertBytes(const std::vector<unsigned char> &bytes, const std::vector<unsigned char> &expected)
{
	if (bytes == expected)
		return;

	std::cerr << "assembler output mismatch\n  actual:  ";
	for (unsigned char byte : bytes)
		std::cerr << std::hex << static_cast<unsigned>(byte) << " ";
	std::cerr << "\n  expected:";
	for (unsigned char byte : expected)
		std::cerr << std::hex << static_cast<unsigned>(byte) << " ";
	std::cerr << std::dec << "\n";
	std::exit(1);
}

int main(void)
{
	g_backend = CreateLegacyXedBackend();
	if (!g_backend) {
		std::cerr << "assembler backend creation failed\n";
		return 1;
	}

	AssertBytes(Assemble("nop", false), {0x90});
	AssertBytes(Assemble("mov eax, ebx", false), {0x89, 0xD8});
	AssertBytes(Assemble("xor rax, rax", true), {0x48, 0x31, 0xC0});
	AssertBytes(Assemble("push rbp", true), {0x55});
	AssertBytes(Assemble("mov [rsp], rax", true), {0x48, 0x89, 0x04, 0x24});
	AssertBytes(Assemble("sub rsp, 0x20", true), {0x48, 0x83, 0xEC, 0x20});
	AssertBytes(Assemble("mov rax, [rbx+8]", true), {0x48, 0x8B, 0x43, 0x08});
	AssertBytes(Assemble("call 0x1010", true), {0xE8, 0x0B, 0x00, 0x00, 0x00});
	AssertBytes(Assemble("jmp 0x1010", true), {0xEB, 0x0E});
#ifdef XEDPARSE_NEW_XED
	AssertBytes(Assemble("vaddps zmm0, zmm1, zmm2", true), {0x62, 0xF1, 0x74, 0x48, 0x58, 0xC2});
#endif
	AssertBytes(Assemble("lock add dword ptr [rax], eax", true), {0xF0, 0x01, 0x00});
	AssertBytes(Assemble("lock xadd dword ptr [rax], eax", true), {0xF0, 0x0F, 0xC1, 0x00});

	AssemblerRequest invalid;
	invalid.instruction = "not_an_instruction";
	invalid.rip = 0x1000;
	invalid.x64 = true;
	AssemblerResult invalid_result;
	if (!FAILED(g_backend->Assemble(invalid, invalid_result))) {
		std::cerr << "invalid instruction unexpectedly succeeded\n";
		return 1;
	}

	AssemblerRequest long_request;
	long_request.instruction.assign(100, 'a');
	long_request.rip = 0x1000;
	long_request.x64 = true;
	AssemblerResult long_result;
	if (!FAILED(g_backend->Assemble(long_request, long_result))) {
		std::cerr << "long instruction unexpectedly succeeded\n";
		return 1;
	}

	std::cout << "assembler tests passed\n";
	return 0;
}
