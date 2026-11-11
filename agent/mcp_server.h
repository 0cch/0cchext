#pragma once

#include <string>

#include "debug_session.h"

class McpServer
{
public:
	explicit McpServer(DebugSession &session);
	int Run();

private:
	DebugSession &session_;

	void HandleMessage(const std::string &line);
	void SendResult(const JsonValue &id, JsonValue result);
	void SendError(const JsonValue &id, int code, const std::string &message);
	JsonValue HandleToolCall(const std::string &name, const JsonValue &arguments);
	JsonValue ToolDefinitions() const;
	JsonValue ToolContent(JsonValue payload, bool is_error = false) const;
};
