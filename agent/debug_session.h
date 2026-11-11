#pragma once

#include <Windows.h>
#include <dbgeng.h>
#include <wrl/client.h>
#include <string>
#include <vector>

#include "json_value.h"

class DebugSession
{
public:
	DebugSession();
	~DebugSession();

	bool OpenDump(const std::wstring &path);
	bool Attach(unsigned long process_id);
	bool Create(const std::wstring &command_line);
	bool IsOpen() const;

	JsonValue Status();
	JsonValue Registers(unsigned long limit);
	JsonValue Modules(unsigned long limit);
	JsonValue Stack(unsigned long limit);
	JsonValue ReadMemory(unsigned long long address, unsigned long size);
	JsonValue ResolveSymbol(unsigned long long address);
	JsonValue Evaluate(const std::string &expression);
	JsonValue Execute(const std::string &command, unsigned long timeout_ms);
	JsonValue Continue(unsigned long timeout_ms);
	bool LoadExtension(const std::wstring &path);

	const std::string &LastError() const;
	void Close();

private:
	Microsoft::WRL::ComPtr<IDebugClient5> client_;
	Microsoft::WRL::ComPtr<IDebugControl> control_;
	Microsoft::WRL::ComPtr<IDebugSymbols> symbols_;
	Microsoft::WRL::ComPtr<IDebugSystemObjects> system_;
	Microsoft::WRL::ComPtr<IDebugDataSpaces> data_;
	Microsoft::WRL::ComPtr<IDebugRegisters> registers_;
	std::string last_error_;

	bool InitializeClient();
	bool WaitForInitialEvent();
	JsonValue ErrorResult(const std::string &code, const std::string &message) const;
	std::string ExecuteRaw(const std::string &command);
};
