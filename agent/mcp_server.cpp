#include "mcp_server.h"

#include <cstdlib>
#include <iostream>
#include <map>
#include <sstream>

namespace
{
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

JsonValue MakeToolSchema(const std::map<std::string, JsonValue> &properties,
	const std::vector<std::string> &required)
{
	std::vector<JsonValue> required_values;
	for (const auto &name : required) required_values.push_back(JsonValue::String(name));
	return JsonValue::Object({
		{"type", JsonValue::String("object")},
		{"properties", JsonValue::Object(properties)},
		{"required", JsonValue::Array(std::move(required_values))},
		{"additionalProperties", JsonValue::Boolean(false)}
	});
}

JsonValue Tool(const std::string &name, const std::string &description, JsonValue schema)
{
	return JsonValue::Object({
		{"name", JsonValue::String(name)},
		{"description", JsonValue::String(description)},
		{"inputSchema", std::move(schema)}
	});
}

JsonValue StringProperty(const std::string &description)
{
	return JsonValue::Object({
		{"type", JsonValue::String("string")},
		{"description", JsonValue::String(description)}
	});
}

JsonValue NumberProperty(const std::string &description, double default_value = -1)
{
	std::map<std::string, JsonValue> values = {
		{"type", JsonValue::String("number")},
		{"description", JsonValue::String(description)}
	};
	if (default_value >= 0) {
		values.emplace("default", JsonValue::Number(default_value));
	}
	return JsonValue::Object(std::move(values));
}

std::wstring Utf8ToWide(const std::string &text)
{
	if (text.empty()) return {};
	int length = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
	if (length <= 0) return {};
	std::wstring result(static_cast<size_t>(length - 1), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, result.data(), length);
	return result;
}

bool ParseAddress(const JsonValue &arguments, unsigned long long &address)
{
	const JsonValue *value = arguments.Get("address");
	if (value == nullptr) return false;
	if (value->GetType() == JsonValue::Type::String) {
		const std::string &text = value->AsString();
		char *end = nullptr;
		address = _strtoui64(text.c_str(), &end, 0);
		return end != text.c_str() && *end == '\0';
	}
	if (value->GetType() == JsonValue::Type::Number) {
		address = static_cast<unsigned long long>(value->AsNumber());
		return true;
	}
	return false;
}

unsigned long LimitFrom(const JsonValue &arguments, unsigned long fallback)
{
	const JsonValue *value = arguments.Get("limit");
	if (value == nullptr || value->GetType() != JsonValue::Type::Number) return fallback;
	const double number = value->AsNumber();
	if (number <= 0) return fallback;
	return static_cast<unsigned long>(number > 4096 ? 4096 : number);
}
}

McpServer::McpServer(DebugSession &session) : session_(session) {}

int McpServer::Run()
{
	std::string line;
	while (std::getline(std::cin, line)) {
		if (line.empty()) continue;
		try {
			HandleMessage(line);
		}
		catch (const std::exception &error) {
			SendError(JsonValue::Null(), -32700, std::string("JSON-RPC error: ") + error.what());
		}
	}
	return 0;
}

void McpServer::SendResult(const JsonValue &id, JsonValue result)
{
	std::cout << SerializeJson(JsonValue::Object({
		{"jsonrpc", JsonValue::String("2.0")},
		{"id", id},
		{"result", std::move(result)}
	})) << std::endl;
}

void McpServer::SendError(const JsonValue &id, int code, const std::string &message)
{
	std::cout << SerializeJson(JsonValue::Object({
		{"jsonrpc", JsonValue::String("2.0")},
		{"id", id},
		{"error", JsonValue::Object({
			{"code", JsonValue::Number(code)},
			{"message", JsonValue::String(message)}
		})}
	})) << std::endl;
}

void McpServer::HandleMessage(const std::string &line)
{
	JsonValue request = ParseJson(line);
	if (!request.IsObject()) {
		SendError(JsonValue::Null(), -32600, "JSON-RPC request must be an object.");
		return;
	}

	const JsonValue *id = request.Get("id");
	const JsonValue *method_value = request.Get("method");
	if (method_value == nullptr || method_value->GetType() != JsonValue::Type::String) {
		SendError(id != nullptr ? *id : JsonValue::Null(), -32600, "Missing JSON-RPC method.");
		return;
	}
	const std::string method = method_value->AsString();
	const bool has_id = id != nullptr;

	if (method == "initialize") {
		JsonValue result = JsonValue::Object({
			{"protocolVersion", JsonValue::String("2024-11-05")},
			{"capabilities", JsonValue::Object({{"tools", JsonValue::Object()}})},
			{"instructions", JsonValue::String("Prefer structured tools over windbg.execute. Treat continue, breakpoints, register writes, memory writes, and arbitrary commands as mutating operations requiring explicit user intent.")},
			{"serverInfo", JsonValue::Object({
				{"name", JsonValue::String("0cchext-agent")},
				{"version", JsonValue::String("1.0.0")}
			})}
		});
		if (has_id) SendResult(*id, std::move(result));
		return;
	}
	if (method == "notifications/initialized" || method == "notifications/cancelled") {
		return;
	}
	if (method == "ping") {
		if (has_id) SendResult(*id, JsonValue::Object());
		return;
	}
	if (method == "tools/list") {
		if (has_id) SendResult(*id, JsonValue::Object({{"tools", ToolDefinitions()}}));
		return;
	}
	if (method == "tools/call") {
		const JsonValue *params = request.Get("params");
		const JsonValue *name = params != nullptr ? params->Get("name") : nullptr;
		const JsonValue *arguments = params != nullptr ? params->Get("arguments") : nullptr;
		if (name == nullptr || name->GetType() != JsonValue::Type::String) {
			if (has_id) SendError(*id, -32602, "tools/call requires params.name.");
			return;
		}
		JsonValue result = HandleToolCall(name->AsString(),
			arguments != nullptr ? *arguments : JsonValue::Object());
		if (has_id) SendResult(*id, std::move(result));
		return;
	}
	if (method == "shutdown") {
		if (has_id) SendResult(*id, JsonValue::Object());
		return;
	}

	if (has_id) SendError(*id, -32601, "Unknown method: " + method);
}

JsonValue McpServer::ToolContent(JsonValue payload, bool is_error) const
{
	const std::string text = SerializeJson(payload);
	return JsonValue::Object({
		{"content", JsonValue::Array({
			JsonValue::Object({
				{"type", JsonValue::String("text")},
				{"text", JsonValue::String(text)}
			})
		})},
		{"isError", JsonValue::Boolean(is_error)}
	});
}

JsonValue McpServer::HandleToolCall(const std::string &name, const JsonValue &arguments)
{
	JsonValue result;
	auto get_limit = [&](const char *key, unsigned long fallback) -> unsigned long {
		const double value = arguments.GetNumber(key, fallback);
		if (value <= 0) return fallback;
		return static_cast<unsigned long>(value > 4096 ? 4096 : value);
	};
	if (name == "windbg.status") {
		result = session_.Status();
	}
	else if (name == "windbg.snapshot") {
		const unsigned long register_limit = get_limit("register_limit", 32);
		const unsigned long module_limit = get_limit("module_limit", 128);
		const unsigned long stack_limit = get_limit("stack_limit", 32);
		result = JsonValue::Object({
			{"ok", JsonValue::Boolean(true)},
			{"data", JsonValue::Object({
				{"status", session_.Status()},
				{"registers", session_.Registers(register_limit)},
				{"modules", session_.Modules(module_limit)},
				{"stack", session_.Stack(stack_limit)}
			})}
		});
	}
	else if (name == "windbg.registers") {
		result = session_.Registers(LimitFrom(arguments, 128));
	}
	else if (name == "windbg.modules") {
		result = session_.Modules(LimitFrom(arguments, 512));
	}
	else if (name == "windbg.stack") {
		result = session_.Stack(LimitFrom(arguments, 64));
	}
	else if (name == "windbg.read_memory") {
		unsigned long long address = 0;
		if (!ParseAddress(arguments, address)) {
			result = MakeError("INVALID_ARGUMENT", "address is required.");
		} else {
			double size = arguments.GetNumber("size", 0);
			if (size <= 0 || size > 1048576) {
				result = MakeError("INVALID_ARGUMENT", "size must be between 1 and 1048576.");
			} else {
				result = session_.ReadMemory(address, static_cast<unsigned long>(size));
			}
		}
	}
	else if (name == "windbg.symbol") {
		unsigned long long address = 0;
		result = ParseAddress(arguments, address)
			? session_.ResolveSymbol(address)
			: MakeError("INVALID_ARGUMENT", "address is required.");
	}
	else if (name == "windbg.evaluate") {
		result = session_.Evaluate(arguments.GetString("expression"));
	}
	else if (name == "windbg.execute") {
		result = session_.Execute(arguments.GetString("command"), static_cast<unsigned long>(arguments.GetNumber("timeout_ms", 30000)));
	}
	else if (name == "windbg.continue") {
		result = session_.Continue(static_cast<unsigned long>(arguments.GetNumber("timeout_ms", 30000)));
	}
	else if (name == "windbg.open_dump") {
		result = session_.OpenDump(Utf8ToWide(arguments.GetString("path")))
			? session_.Status()
			: MakeError("OPEN_FAILED", session_.LastError());
	}
	else if (name == "windbg.attach") {
		const double pid = arguments.GetNumber("process_id", 0);
		result = pid > 0 && session_.Attach(static_cast<unsigned long>(pid))
			? session_.Status()
			: MakeError("ATTACH_FAILED", session_.LastError());
	}
	else if (name == "windbg.create") {
		result = session_.Create(Utf8ToWide(arguments.GetString("command_line")))
			? session_.Status()
			: MakeError("CREATE_FAILED", session_.LastError());
	}
	else if (name == "windbg.load_extension") {
		const bool loaded = session_.LoadExtension(Utf8ToWide(arguments.GetString("path")));
		result = loaded ? JsonValue::Object({{"ok", JsonValue::Boolean(true)}}
			) : MakeError("LOAD_FAILED", "Unable to load extension.");
	}
	else {
		return ToolContent(MakeError("UNKNOWN_TOOL", "Unknown tool: " + name), true);
	}

	const JsonValue *ok = result.Get("ok");
	return ToolContent(result, ok == nullptr || !ok->AsBoolean());
}

JsonValue McpServer::ToolDefinitions() const
{
	std::vector<JsonValue> tools;
	tools.push_back(Tool("windbg.status", "Return debugger, process, thread, and last-event status.",
		MakeToolSchema({}, {})));
	tools.push_back(Tool("windbg.snapshot", "Return a compact status, register, module, and stack snapshot.",
		MakeToolSchema({
			{"register_limit", NumberProperty("Maximum number of registers.", 32)},
			{"module_limit", NumberProperty("Maximum number of modules.", 128)},
			{"stack_limit", NumberProperty("Maximum number of frames.", 32)}
		}, {})));
	tools.push_back(Tool("windbg.registers", "Read the current thread's register values.",
		MakeToolSchema({{"limit", NumberProperty("Maximum number of registers.", 128)}}, {})));
	tools.push_back(Tool("windbg.modules", "List loaded modules and their base addresses.",
		MakeToolSchema({{"limit", NumberProperty("Maximum number of modules.", 512)}}, {})));
	tools.push_back(Tool("windbg.stack", "Return a symbol-resolved stack trace for the current thread.",
		MakeToolSchema({{"limit", NumberProperty("Maximum number of frames.", 64)}}, {})));
	tools.push_back(Tool("windbg.read_memory", "Read target memory and return hex plus printable ASCII.",
		MakeToolSchema({
			{"address", StringProperty("Address as a hexadecimal string or integer.")},
			{"size", NumberProperty("Number of bytes to read, maximum 1 MiB.")}
		}, {"address", "size"})));
	tools.push_back(Tool("windbg.symbol", "Resolve an address to the nearest symbol.",
		MakeToolSchema({{"address", StringProperty("Address as a hexadecimal string or integer.")}}, {"address"})));
	tools.push_back(Tool("windbg.evaluate", "Evaluate a WinDbg expression.",
		MakeToolSchema({{"expression", StringProperty("WinDbg expression, for example ntdll!RtlSizeHeap.")}}, {"expression"})));
	tools.push_back(Tool("windbg.execute", "Execute a WinDbg/cdb command and return captured text output.",
		MakeToolSchema({
			{"command", StringProperty("Debugger command to execute.")},
			{"timeout_ms", NumberProperty("Reserved execution timeout in milliseconds.", 30000)}
		}, {"command"})));
	tools.push_back(Tool("windbg.continue", "Continue the target until the next debugger event or timeout.",
		MakeToolSchema({{"timeout_ms", NumberProperty("Wait timeout in milliseconds.", 30000)}}, {})));
	tools.push_back(Tool("windbg.open_dump", "Open a crash dump file.",
		MakeToolSchema({{"path", StringProperty("Path to the dump file.")}}, {"path"})));
	tools.push_back(Tool("windbg.attach", "Attach to a running process by process ID.",
		MakeToolSchema({{"process_id", NumberProperty("Windows process ID.")}}, {"process_id"})));
	tools.push_back(Tool("windbg.create", "Create and debug a process.",
		MakeToolSchema({{"command_line", StringProperty("Command line to launch.")}}, {"command_line"})));
	tools.push_back(Tool("windbg.load_extension", "Load a WinDbg extension DLL into the current session.",
		MakeToolSchema({{"path", StringProperty("Extension DLL path.")}}, {"path"})));
	return JsonValue::Array(std::move(tools));
}
