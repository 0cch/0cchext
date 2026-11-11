#include "debug_session.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace
{
class OutputCapture final : public IDebugOutputCallbacks
{
public:
	STDMETHOD(QueryInterface)(REFIID iid, void **object) override
	{
		if (object == nullptr) return E_POINTER;
		*object = nullptr;
		if (iid == __uuidof(IUnknown) || iid == __uuidof(IDebugOutputCallbacks)) {
			*object = this;
			AddRef();
			return S_OK;
		}
		return E_NOINTERFACE;
	}

	STDMETHOD_(ULONG, AddRef)() override { return 1; }
	STDMETHOD_(ULONG, Release)() override { return 0; }

	STDMETHOD(Output)(ULONG, PCSTR text) override
	{
		if (text != nullptr && output_.size() < kMaxOutput) {
			output_.append(text, (std::min)(strlen(text), kMaxOutput - output_.size()));
		}
		return S_OK;
	}

	const std::string &Output() const { return output_; }
	void Clear() { output_.clear(); }

private:
	static constexpr size_t kMaxOutput = 4 * 1024 * 1024;
	std::string output_;
};

class ScopedNullStdHandles
{
public:
	ScopedNullStdHandles()
	{
		input_ = GetStdHandle(STD_INPUT_HANDLE);
		output_ = GetStdHandle(STD_OUTPUT_HANDLE);
		error_ = GetStdHandle(STD_ERROR_HANDLE);
		nul_ = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
		if (nul_ != INVALID_HANDLE_VALUE) {
			SetStdHandle(STD_INPUT_HANDLE, nul_);
			SetStdHandle(STD_OUTPUT_HANDLE, nul_);
			SetStdHandle(STD_ERROR_HANDLE, nul_);
		}
	}

	~ScopedNullStdHandles()
	{
		if (nul_ != INVALID_HANDLE_VALUE) {
			SetStdHandle(STD_INPUT_HANDLE, input_);
			SetStdHandle(STD_OUTPUT_HANDLE, output_);
			SetStdHandle(STD_ERROR_HANDLE, error_);
			CloseHandle(nul_);
		}
	}

private:
	HANDLE input_ = INVALID_HANDLE_VALUE;
	HANDLE output_ = INVALID_HANDLE_VALUE;
	HANDLE error_ = INVALID_HANDLE_VALUE;
	HANDLE nul_ = INVALID_HANDLE_VALUE;
};

std::string HexValue(ULONG64 value)
{
	char buffer[32] = {0};
	sprintf_s(buffer, "0x%016I64X", value);
	return buffer;
}

std::string HResultText(HRESULT hr)
{
	char buffer[32] = {0};
	sprintf_s(buffer, "0x%08X", static_cast<unsigned>(hr));
	return buffer;
}

JsonValue MakeError(const std::string &code, const std::string &message)
{
	return JsonValue::Object({
		{"ok", JsonValue::Boolean(false)},
		{"error", JsonValue::Object({
			{"code", JsonValue::String(code)},
			{"message", JsonValue::String(message)}
		})}
	});
}

JsonValue MakeOk(JsonValue data)
{
	return JsonValue::Object({
		{"ok", JsonValue::Boolean(true)},
		{"data", std::move(data)}
	});
}
}

DebugSession::DebugSession() = default;

DebugSession::~DebugSession()
{
	Close();
}

bool DebugSession::InitializeClient()
{
	Microsoft::WRL::ComPtr<IDebugClient> base;
	HRESULT hr = DebugCreate(__uuidof(IDebugClient), &base);
	if (FAILED(hr)) {
		last_error_ = "DebugCreate failed: " + HResultText(hr);
		return false;
	}
	if (FAILED(base.As(&client_)) || FAILED(client_.As(&control_)) ||
		FAILED(client_.As(&symbols_)) || FAILED(client_.As(&system_)) ||
		FAILED(client_.As(&data_)) || FAILED(client_.As(&registers_))) {
		last_error_ = "Unable to query required DbgEng interfaces.";
		return false;
	}

	ULONG engine_options = 0;
	if (SUCCEEDED(control_->GetEngineOptions(&engine_options))) {
		control_->SetEngineOptions(engine_options | DEBUG_ENGOPT_INITIAL_BREAK);
	}
	return true;
}

bool DebugSession::WaitForInitialEvent()
{
	if (control_ == nullptr) {
		last_error_ = "Debugger control interface is unavailable.";
		return false;
	}
	HRESULT hr = control_->WaitForEvent(0, 30000);
	if (hr == S_FALSE) {
		last_error_ = "Timed out waiting for the initial debugger event.";
		return false;
	}
	if (FAILED(hr)) {
		last_error_ = "WaitForEvent failed: " + HResultText(hr);
		return false;
	}
	return true;
}

bool DebugSession::OpenDump(const std::wstring &path)
{
	Close();
	if (!InitializeClient()) return false;
	HRESULT hr = client_->OpenDumpFileWide(path.c_str(), 0);
	if (FAILED(hr)) {
		last_error_ = "OpenDumpFileWide failed: " + HResultText(hr);
		return false;
	}
	return WaitForInitialEvent();
}

bool DebugSession::Attach(unsigned long process_id)
{
	Close();
	if (!InitializeClient()) return false;
	HRESULT hr = client_->AttachProcess(0, process_id, DEBUG_ATTACH_DEFAULT);
	if (FAILED(hr)) {
		last_error_ = "AttachProcess failed: " + HResultText(hr);
		return false;
	}
	return WaitForInitialEvent();
}

bool DebugSession::Create(const std::wstring &command_line)
{
	Close();
	if (!InitializeClient()) return false;
	ScopedNullStdHandles null_handles;
	HRESULT hr = client_->CreateProcessWide(0, const_cast<wchar_t *>(command_line.c_str()), DEBUG_ONLY_THIS_PROCESS);
	if (FAILED(hr)) {
		last_error_ = "CreateProcessWide failed: " + HResultText(hr);
		return false;
	}
	return WaitForInitialEvent();
}

bool DebugSession::IsOpen() const
{
	return control_ != nullptr;
}

const std::string &DebugSession::LastError() const
{
	return last_error_;
}

JsonValue DebugSession::ErrorResult(const std::string &code, const std::string &message) const
{
	return MakeError(code, message);
}

JsonValue DebugSession::Status()
{
	if (!IsOpen()) return ErrorResult("NO_SESSION", "No debugger session is open.");

	ULONG class_type = 0;
	ULONG qualifier = 0;
	ULONG execution_status = 0;
	ULONG process_id = 0;
	ULONG thread_id = 0;
	ULONG thread_count = 0;
	ULONG event_type = 0;
	ULONG event_process_id = 0;
	ULONG event_thread_id = 0;
	char event_description[512] = {0};
	ULONG event_description_size = 0;

	HRESULT hr = control_->GetDebuggeeType(&class_type, &qualifier);
	if (FAILED(hr)) return ErrorResult("DBGENG_ERROR", "GetDebuggeeType failed: " + HResultText(hr));
	hr = control_->GetExecutionStatus(&execution_status);
	if (FAILED(hr)) return ErrorResult("DBGENG_ERROR", "GetExecutionStatus failed: " + HResultText(hr));
	system_->GetCurrentProcessId(&process_id);
	system_->GetCurrentThreadId(&thread_id);
	system_->GetNumberThreads(&thread_count);
	control_->GetLastEventInformation(&event_type, &event_process_id, &event_thread_id, nullptr, 0, nullptr,
		event_description, _countof(event_description), &event_description_size);
	if (process_id == 0) process_id = event_process_id;
	if (thread_id == 0) thread_id = event_thread_id;

	const char *debuggee = class_type == DEBUG_CLASS_KERNEL ? "kernel" : "user";
	const char *state = execution_status == DEBUG_STATUS_BREAK ? "break" :
		execution_status == DEBUG_STATUS_GO ? "running" : "unknown";

	return MakeOk(JsonValue::Object({
		{"architecture", JsonValue::String(sizeof(void *) == 8 ? "x64" : "x86")},
		{"debuggee_class", JsonValue::String(debuggee)},
		{"qualifier", JsonValue::Number(qualifier)},
		{"state", JsonValue::String(state)},
		{"process_id", JsonValue::Number(process_id)},
		{"thread_id", JsonValue::Number(thread_id)},
		{"thread_count", JsonValue::Number(thread_count)},
		{"last_event_type", JsonValue::Number(event_type)},
		{"last_event", JsonValue::String(event_description)}
	}));
}

JsonValue DebugSession::Registers(unsigned long limit)
{
	if (!IsOpen()) return ErrorResult("NO_SESSION", "No debugger session is open.");
	if (limit == 0 || limit > 512) limit = 128;

	ULONG count = 0;
	HRESULT hr = registers_->GetNumberRegisters(&count);
	if (FAILED(hr)) return ErrorResult("DBGENG_ERROR", "GetNumberRegisters failed: " + HResultText(hr));

	std::vector<JsonValue> values;
	for (ULONG i = 0; i < count && values.size() < limit; ++i) {
		char name[128] = {0};
		ULONG name_size = 0;
		DEBUG_REGISTER_DESCRIPTION description = {};
		DEBUG_VALUE value = {};
		if (FAILED(registers_->GetDescription(i, name, _countof(name), &name_size, &description)) ||
			FAILED(registers_->GetValue(i, &value))) {
			continue;
		}
		values.push_back(JsonValue::Object({
			{"name", JsonValue::String(name)},
			{"value", JsonValue::String(HexValue(value.I64))},
			{"type", JsonValue::Number(description.Type)}
		}));
	}
	return MakeOk(JsonValue::Array(std::move(values)));
}

JsonValue DebugSession::Modules(unsigned long limit)
{
	if (!IsOpen()) return ErrorResult("NO_SESSION", "No debugger session is open.");
	if (limit == 0 || limit > 4096) limit = 512;

	ULONG loaded = 0;
	ULONG unloaded = 0;
	HRESULT hr = symbols_->GetNumberModules(&loaded, &unloaded);
	if (FAILED(hr)) return ErrorResult("DBGENG_ERROR", "GetNumberModules failed: " + HResultText(hr));

	std::vector<JsonValue> values;
	for (ULONG i = 0; i < loaded && values.size() < limit; ++i) {
		ULONG64 base = 0;
		char image_name[512] = {0};
		char module_name[256] = {0};
		char loaded_name[1024] = {0};
		if (FAILED(symbols_->GetModuleByIndex(i, &base)) ||
			FAILED(symbols_->GetModuleNames(i, base, image_name, _countof(image_name), nullptr,
				module_name, _countof(module_name), nullptr,
				loaded_name, _countof(loaded_name), nullptr))) {
			continue;
		}
		values.push_back(JsonValue::Object({
			{"index", JsonValue::Number(i)},
			{"base", JsonValue::String(HexValue(base))},
			{"image", JsonValue::String(image_name)},
			{"module", JsonValue::String(module_name)},
			{"loaded_image", JsonValue::String(loaded_name)}
		}));
	}
	return MakeOk(JsonValue::Object({
		{"loaded_count", JsonValue::Number(loaded)},
		{"unloaded_count", JsonValue::Number(unloaded)},
		{"modules", JsonValue::Array(std::move(values))}
	}));
}

JsonValue DebugSession::Stack(unsigned long limit)
{
	if (!IsOpen()) return ErrorResult("NO_SESSION", "No debugger session is open.");
	if (limit == 0 || limit > 256) limit = 64;

	std::vector<DEBUG_STACK_FRAME> frames(limit);
	ULONG filled = 0;
	HRESULT hr = control_->GetStackTrace(0, 0, 0, frames.data(), static_cast<ULONG>(frames.size()), &filled);
	if (FAILED(hr)) return ErrorResult("DBGENG_ERROR", "GetStackTrace failed: " + HResultText(hr));

	std::vector<JsonValue> values;
	for (ULONG i = 0; i < filled; ++i) {
		char name[512] = {0};
		ULONG name_size = 0;
		ULONG64 displacement = 0;
		symbols_->GetNameByOffset(frames[i].InstructionOffset, name, _countof(name), &name_size, &displacement);
		values.push_back(JsonValue::Object({
			{"index", JsonValue::Number(i)},
			{"instruction", JsonValue::String(HexValue(frames[i].InstructionOffset))},
			{"return", JsonValue::String(HexValue(frames[i].ReturnOffset))},
			{"frame", JsonValue::String(HexValue(frames[i].FrameOffset))},
			{"symbol", JsonValue::String(name)},
			{"displacement", JsonValue::String(HexValue(displacement))}
		}));
	}
	return MakeOk(JsonValue::Array(std::move(values)));
}

JsonValue DebugSession::ReadMemory(unsigned long long address, unsigned long size)
{
	if (!IsOpen()) return ErrorResult("NO_SESSION", "No debugger session is open.");
	if (size == 0) return ErrorResult("INVALID_ARGUMENT", "size must be greater than zero.");
	if (size > 1024 * 1024) return ErrorResult("LIMIT_EXCEEDED", "size exceeds the 1 MiB limit.");

	std::vector<unsigned char> bytes(size);
	ULONG read = 0;
	HRESULT hr = data_->ReadVirtual(address, bytes.data(), size, &read);
	if (FAILED(hr) || read == 0) {
		return ErrorResult("INVALID_ADDRESS", "Unable to read memory at " + HexValue(address) + ".");
	}

	std::ostringstream hex;
	hex << std::hex << std::setfill('0');
	for (ULONG i = 0; i < read; ++i) {
		hex << std::setw(2) << static_cast<unsigned>(bytes[i]);
	}
	std::string ascii;
	for (ULONG i = 0; i < read; ++i) {
		ascii.push_back(bytes[i] >= 0x20 && bytes[i] < 0x7f ? static_cast<char>(bytes[i]) : '.');
	}
	return MakeOk(JsonValue::Object({
		{"address", JsonValue::String(HexValue(address))},
		{"requested", JsonValue::Number(size)},
		{"read", JsonValue::Number(read)},
		{"hex", JsonValue::String(hex.str())},
		{"ascii", JsonValue::String(ascii)}
	}));
}

JsonValue DebugSession::ResolveSymbol(unsigned long long address)
{
	if (!IsOpen()) return ErrorResult("NO_SESSION", "No debugger session is open.");
	char name[1024] = {0};
	ULONG name_size = 0;
	ULONG64 displacement = 0;
	HRESULT hr = symbols_->GetNameByOffset(address, name, _countof(name), &name_size, &displacement);
	if (FAILED(hr) || name[0] == '\0') {
		return ErrorResult("SYMBOL_NOT_FOUND", "No symbol was found for " + HexValue(address) + ".");
	}
	return MakeOk(JsonValue::Object({
		{"address", JsonValue::String(HexValue(address))},
		{"symbol", JsonValue::String(name)},
		{"displacement", JsonValue::String(HexValue(displacement))}
	}));
}

JsonValue DebugSession::Evaluate(const std::string &expression)
{
	if (!IsOpen()) return ErrorResult("NO_SESSION", "No debugger session is open.");
	DEBUG_VALUE value = {};
	ULONG remainder = 0;
	HRESULT hr = control_->Evaluate(expression.c_str(), DEBUG_VALUE_INT64, &value, &remainder);
	if (FAILED(hr)) return ErrorResult("EVALUATION_FAILED", "Unable to evaluate the expression.");
	return MakeOk(JsonValue::Object({
		{"value", JsonValue::String(HexValue(value.I64))},
		{"remainder", JsonValue::Number(remainder)}
	}));
}

std::string DebugSession::ExecuteRaw(const std::string &command)
{
	if (!IsOpen()) return "";
	Microsoft::WRL::ComPtr<IDebugOutputCallbacks> previous;
	OutputCapture capture;
	client_->GetOutputCallbacks(&previous);
	client_->SetOutputCallbacks(&capture);
	control_->Execute(DEBUG_OUTCTL_THIS_CLIENT | DEBUG_OUTCTL_OVERRIDE_MASK | DEBUG_OUTCTL_NOT_LOGGED,
		command.c_str(), DEBUG_EXECUTE_NOT_LOGGED | DEBUG_EXECUTE_NO_REPEAT);
	if (previous != nullptr) {
		client_->SetOutputCallbacks(previous.Get());
	} else {
		client_->SetOutputCallbacks(nullptr);
	}
	return capture.Output();
}

JsonValue DebugSession::Execute(const std::string &command, unsigned long timeout_ms)
{
	UNREFERENCED_PARAMETER(timeout_ms);
	if (!IsOpen()) return ErrorResult("NO_SESSION", "No debugger session is open.");
	if (command.empty()) return ErrorResult("INVALID_ARGUMENT", "command must not be empty.");

	Microsoft::WRL::ComPtr<IDebugOutputCallbacks> previous;
	OutputCapture capture;
	client_->GetOutputCallbacks(&previous);
	client_->SetOutputCallbacks(&capture);
	HRESULT hr = control_->Execute(DEBUG_OUTCTL_THIS_CLIENT | DEBUG_OUTCTL_OVERRIDE_MASK | DEBUG_OUTCTL_NOT_LOGGED,
		command.c_str(), DEBUG_EXECUTE_NOT_LOGGED | DEBUG_EXECUTE_NO_REPEAT);
	if (previous != nullptr) {
		client_->SetOutputCallbacks(previous.Get());
	} else {
		client_->SetOutputCallbacks(nullptr);
	}
	if (FAILED(hr)) return ErrorResult("EXECUTION_FAILED", "Debugger command failed: " + HResultText(hr));
	return MakeOk(JsonValue::Object({
		{"output", JsonValue::String(capture.Output())}
	}));
}

JsonValue DebugSession::Continue(unsigned long timeout_ms)
{
	if (!IsOpen()) return ErrorResult("NO_SESSION", "No debugger session is open.");
	if (timeout_ms == 0) timeout_ms = 30000;
	HRESULT hr = control_->SetExecutionStatus(DEBUG_STATUS_GO);
	if (FAILED(hr)) return ErrorResult("EXECUTION_FAILED", "Unable to continue the target: " + HResultText(hr));
	hr = control_->WaitForEvent(0, timeout_ms);
	if (hr == S_FALSE) return ErrorResult("TIMEOUT", "The target did not stop before the timeout.");
	if (FAILED(hr)) {
		ULONG current_status = 0;
		if (SUCCEEDED(control_->GetExecutionStatus(&current_status)) &&
			(current_status & DEBUG_STATUS_MASK) == DEBUG_STATUS_NO_DEBUGGEE) {
			return MakeOk(JsonValue::Object({{"state", JsonValue::String("exited")}}));
		}
		return ErrorResult("EXECUTION_FAILED", "WaitForEvent failed: " + HResultText(hr));
	}
	return Status();
}

bool DebugSession::LoadExtension(const std::wstring &path)
{
	if (!IsOpen()) return false;
	std::string command = ".load \"";
	for (wchar_t c : path) {
		if (c < 0x80) command.push_back(static_cast<char>(c));
		else return false;
	}
	command += "\"";
	ExecuteRaw(command);
	return true;
}

void DebugSession::Close()
{
	if (client_ != nullptr) {
		client_->EndSession(DEBUG_END_PASSIVE);
	}
	client_.Reset();
	control_.Reset();
	symbols_.Reset();
	system_.Reset();
	data_.Reset();
	registers_.Reset();
	last_error_.clear();
}
